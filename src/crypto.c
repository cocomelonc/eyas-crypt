#include "eyas_crypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
#else
#include <fcntl.h>
#include <unistd.h>
#endif

static uint32_t load32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void store32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static uint32_t rotl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

#define QR(a, b, c, d) \
  do {                 \
    a += b;            \
    d ^= a;            \
    d = rotl(d, 16);   \
    c += d;            \
    b ^= c;            \
    b = rotl(b, 12);   \
    a += b;            \
    d ^= a;            \
    d = rotl(d, 8);    \
    c += d;            \
    b ^= c;            \
    b = rotl(b, 7);    \
  } while (0)

static void chacha_block(uint8_t out[64], const uint8_t key[32], uint32_t ctr, const uint8_t nonce[12]) {
  static const uint8_t sig[16] = "expand 32-byte k";
  uint32_t x[16], w[16];
  x[0] = load32(sig);
  x[1] = load32(sig + 4);
  x[2] = load32(sig + 8);
  x[3] = load32(sig + 12);
  for (size_t i = 0; i < 8; i++) x[4 + i] = load32(key + i * 4);
  x[12] = ctr;
  x[13] = load32(nonce);
  x[14] = load32(nonce + 4);
  x[15] = load32(nonce + 8);
  memcpy(w, x, sizeof(w));
  for (size_t i = 0; i < 10; i++) {
    QR(w[0], w[4], w[8], w[12]);
    QR(w[1], w[5], w[9], w[13]);
    QR(w[2], w[6], w[10], w[14]);
    QR(w[3], w[7], w[11], w[15]);
    QR(w[0], w[5], w[10], w[15]);
    QR(w[1], w[6], w[11], w[12]);
    QR(w[2], w[7], w[8], w[13]);
    QR(w[3], w[4], w[9], w[14]);
  }
  for (size_t i = 0; i < 16; i++) store32(out + i * 4, w[i] + x[i]);
}

void eyas_chacha20_xor(uint8_t *buf, size_t len, const uint8_t key[32], const uint8_t nonce[12]) {
  uint32_t ctr = 1;
  for (size_t off = 0; off < len;) {
    uint8_t block[64];
    size_t n = len - off > 64 ? 64 : len - off;
    chacha_block(block, key, ctr++, nonce);
    for (size_t i = 0; i < n; i++) buf[off + i] ^= block[i];
    off += n;
  }
}

void eyas_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
  uint8_t k0[64], ipad[64], opad[64], inner[32];
  uint8_t *tmp;
  memset(k0, 0, sizeof(k0));
  if (key_len > 64) eyas_sha256(key, key_len, k0);
  else memcpy(k0, key, key_len);
  for (size_t i = 0; i < 64; i++) {
    ipad[i] = (uint8_t)(k0[i] ^ 0x36U);
    opad[i] = (uint8_t)(k0[i] ^ 0x5cU);
  }
  tmp = (uint8_t *)malloc(64 + msg_len);
  if (!tmp) {
    memset(out, 0, 32);
    return;
  }
  memcpy(tmp, ipad, 64);
  memcpy(tmp + 64, msg, msg_len);
  eyas_sha256(tmp, 64 + msg_len, inner);
  free(tmp);
  tmp = (uint8_t *)malloc(96);
  if (!tmp) {
    memset(out, 0, 32);
    return;
  }
  memcpy(tmp, opad, 64);
  memcpy(tmp + 64, inner, 32);
  eyas_sha256(tmp, 96, out);
  free(tmp);
}

void eyas_pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t salt_len, uint32_t iters, uint8_t *out, size_t out_len) {
  uint32_t block_index = 1;
  size_t produced = 0;
  while (produced < out_len) {
    uint8_t u[32], t[32], *msg;
    size_t take = out_len - produced > 32 ? 32 : out_len - produced;
    msg = (uint8_t *)malloc(salt_len + 4);
    if (!msg) return;
    memcpy(msg, salt, salt_len);
    msg[salt_len] = (uint8_t)(block_index >> 24);
    msg[salt_len + 1] = (uint8_t)(block_index >> 16);
    msg[salt_len + 2] = (uint8_t)(block_index >> 8);
    msg[salt_len + 3] = (uint8_t)block_index;
    eyas_hmac_sha256((const uint8_t *)pass, strlen(pass), msg, salt_len + 4, u);
    memcpy(t, u, 32);
    free(msg);
    for (uint32_t i = 1; i < iters; i++) {
      eyas_hmac_sha256((const uint8_t *)pass, strlen(pass), u, 32, u);
      for (size_t j = 0; j < 32; j++) t[j] ^= u[j];
    }
    memcpy(out + produced, t, take);
    produced += take;
    block_index++;
  }
}

int eyas_random(uint8_t *buf, size_t len) {
#ifdef _WIN32
  return SystemFunction036(buf, (ULONG)len) ? 0 : -1;
#else
  int fd = open("/dev/urandom", O_RDONLY);
  size_t got = 0;
  if (fd < 0) return -1;
  while (got < len) {
    ssize_t n = read(fd, buf + got, len - got);
    if (n <= 0) {
      close(fd);
      return -1;
    }
    got += (size_t)n;
  }
  close(fd);
  return 0;
#endif
}

void eyas_hex_encode(const uint8_t *in, size_t len, char *out) {
  static const char *h = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = h[in[i] >> 4];
    out[i * 2 + 1] = h[in[i] & 15U];
  }
  out[len * 2] = '\0';
}

static int hv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int eyas_hex_decode(const char *in, uint8_t *out, size_t out_len, size_t *written) {
  size_t len = strlen(in);
  if ((len & 1U) || len / 2 > out_len) return -1;
  for (size_t i = 0; i < len / 2; i++) {
    int a = hv(in[i * 2]), b = hv(in[i * 2 + 1]);
    if (a < 0 || b < 0) return -1;
    out[i] = (uint8_t)((a << 4) | b);
  }
  *written = len / 2;
  return 0;
}

int eyas_ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t d = 0;
  for (size_t i = 0; i < len; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}
