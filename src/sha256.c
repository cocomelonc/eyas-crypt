/*
 * sha256.c
 * author: @cocomelonc
 * https://cocomelonc.github.io
*/
#include "eyas_crypt.h"

#include <string.h>

typedef struct {
  uint32_t s[8];
  uint64_t bits;
  uint8_t buf[64];
  size_t len;
} sha256_ctx;

static const uint32_t k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32U - n)); }

static void block(sha256_ctx *c, const uint8_t d[64]) {
  uint32_t a, b, e, f, g, h, m[64], cc, dd;
  for (size_t i = 0; i < 16; i++)
    m[i] = ((uint32_t)d[i * 4] << 24) | ((uint32_t)d[i * 4 + 1] << 16) | ((uint32_t)d[i * 4 + 2] << 8) | d[i * 4 + 3];
  for (size_t i = 16; i < 64; i++) {
    uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
    uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }
  a = c->s[0];
  b = c->s[1];
  cc = c->s[2];
  dd = c->s[3];
  e = c->s[4];
  f = c->s[5];
  g = c->s[6];
  h = c->s[7];
  for (size_t i = 0; i < 64; i++) {
    uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + s1 + ch + k[i] + m[i];
    uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
    uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = dd + t1;
    dd = cc;
    cc = b;
    b = a;
    a = t1 + t2;
  }
  c->s[0] += a;
  c->s[1] += b;
  c->s[2] += cc;
  c->s[3] += dd;
  c->s[4] += e;
  c->s[5] += f;
  c->s[6] += g;
  c->s[7] += h;
}

static void init(sha256_ctx *c) {
  c->s[0] = 0x6a09e667U;
  c->s[1] = 0xbb67ae85U;
  c->s[2] = 0x3c6ef372U;
  c->s[3] = 0xa54ff53aU;
  c->s[4] = 0x510e527fU;
  c->s[5] = 0x9b05688cU;
  c->s[6] = 0x1f83d9abU;
  c->s[7] = 0x5be0cd19U;
  c->bits = 0;
  c->len = 0;
}

static void update(sha256_ctx *c, const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    c->buf[c->len++] = p[i];
    if (c->len == 64) {
      block(c, c->buf);
      c->bits += 512;
      c->len = 0;
    }
  }
}

static void done(sha256_ctx *c, uint8_t out[32]) {
  size_t i = c->len;
  c->buf[i++] = 0x80;
  if (i > 56) {
    while (i < 64) c->buf[i++] = 0;
    block(c, c->buf);
    i = 0;
  }
  while (i < 56) c->buf[i++] = 0;
  c->bits += c->len * 8;
  for (i = 0; i < 8; i++) c->buf[63 - i] = (uint8_t)(c->bits >> (i * 8));
  block(c, c->buf);
  for (i = 0; i < 4; i++)
    for (size_t j = 0; j < 8; j++)
      out[i + j * 4] = (uint8_t)((c->s[j] >> (24 - i * 8)) & 0xffU);
}

void eyas_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  sha256_ctx c;
  init(&c);
  update(&c, data, len);
  done(&c, out);
}

void eyas_sha256_hex(const uint8_t *data, size_t len, char out[EYAS_HASH_HEX]) {
  static const char *hex = "0123456789abcdef";
  uint8_t h[32];
  eyas_sha256(data, len, h);
  for (size_t i = 0; i < 32; i++) {
    out[i * 2] = hex[h[i] >> 4];
    out[i * 2 + 1] = hex[h[i] & 15U];
  }
  out[64] = '\0';
}
