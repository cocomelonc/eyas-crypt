#include "eyas_crypt.h"

#include <stdlib.h>
#include <string.h>

/*
 * Argon2id (RFC 9106), memory-hard password hashing, on top of a BLAKE2b
 * implementation. Verified against the RFC 9106 test vector at build time
 * (see tests/smoke.sh). Optional alternative to PBKDF2-HMAC-SHA256: the
 * memory-hard design raises the cost of GPU/ASIC password cracking.
 */

static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static uint64_t load64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
  return v;
}
static void store64(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void store32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* - BLAKE2b - */

static const uint64_t b2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static const uint8_t b2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

typedef struct {
  uint64_t h[8];
  uint64_t t[2];
  uint8_t buf[128];
  size_t buflen;
  size_t outlen;
} b2b_ctx;

#define B2B_G(a, b, c, d, x, y) \
  do {                          \
    a = a + b + x;              \
    d = rotr64(d ^ a, 32);      \
    c = c + d;                  \
    b = rotr64(b ^ c, 24);      \
    a = a + b + y;              \
    d = rotr64(d ^ a, 16);      \
    c = c + d;                  \
    b = rotr64(b ^ c, 63);      \
  } while (0)

static void b2b_compress(b2b_ctx *s, const uint8_t *block, int last) {
  uint64_t m[16], v[16];
  for (int i = 0; i < 16; i++) m[i] = load64(block + 8 * i);
  for (int i = 0; i < 8; i++) v[i] = s->h[i];
  for (int i = 0; i < 8; i++) v[8 + i] = b2b_iv[i];
  v[12] ^= s->t[0];
  v[13] ^= s->t[1];
  if (last) v[14] = ~v[14];
  for (int r = 0; r < 12; r++) {
    const uint8_t *sig = b2b_sigma[r];
    B2B_G(v[0], v[4], v[8], v[12], m[sig[0]], m[sig[1]]);
    B2B_G(v[1], v[5], v[9], v[13], m[sig[2]], m[sig[3]]);
    B2B_G(v[2], v[6], v[10], v[14], m[sig[4]], m[sig[5]]);
    B2B_G(v[3], v[7], v[11], v[15], m[sig[6]], m[sig[7]]);
    B2B_G(v[0], v[5], v[10], v[15], m[sig[8]], m[sig[9]]);
    B2B_G(v[1], v[6], v[11], v[12], m[sig[10]], m[sig[11]]);
    B2B_G(v[2], v[7], v[8], v[13], m[sig[12]], m[sig[13]]);
    B2B_G(v[3], v[4], v[9], v[14], m[sig[14]], m[sig[15]]);
  }
  for (int i = 0; i < 8; i++) s->h[i] ^= v[i] ^ v[8 + i];
}

static void b2b_init(b2b_ctx *s, size_t outlen) {
  memset(s, 0, sizeof(*s));
  for (int i = 0; i < 8; i++) s->h[i] = b2b_iv[i];
  s->h[0] ^= 0x01010000ULL ^ (uint64_t)outlen;
  s->outlen = outlen;
}

static void b2b_update(b2b_ctx *s, const uint8_t *in, size_t inlen) {
  while (inlen > 0) {
    if (s->buflen == 128) {
      s->t[0] += 128;
      if (s->t[0] < 128) s->t[1]++;
      b2b_compress(s, s->buf, 0);
      s->buflen = 0;
    }
    size_t take = 128 - s->buflen;
    if (take > inlen) take = inlen;
    memcpy(s->buf + s->buflen, in, take);
    s->buflen += take;
    in += take;
    inlen -= take;
  }
}

static void b2b_final(b2b_ctx *s, uint8_t *out) {
  uint8_t tmp[64];
  s->t[0] += s->buflen;
  if (s->t[0] < s->buflen) s->t[1]++;
  memset(s->buf + s->buflen, 0, 128 - s->buflen);
  b2b_compress(s, s->buf, 1);
  for (int i = 0; i < 8; i++) store64(tmp + 8 * i, s->h[i]);
  memcpy(out, tmp, s->outlen);
}

static void blake2b(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
  b2b_ctx s;
  b2b_init(&s, outlen);
  b2b_update(&s, in, inlen);
  b2b_final(&s, out);
}

/* Variable-length hash H' (RFC 9106 section 3.2). */
static void blake2b_long(uint8_t *out, uint32_t outlen, const uint8_t *in, size_t inlen) {
  uint8_t len_le[4], buf[64];
  store32(len_le, outlen);
  if (outlen <= 64) {
    b2b_ctx s;
    b2b_init(&s, outlen);
    b2b_update(&s, len_le, 4);
    b2b_update(&s, in, inlen);
    b2b_final(&s, out);
    return;
  }
  b2b_ctx s;
  b2b_init(&s, 64);
  b2b_update(&s, len_le, 4);
  b2b_update(&s, in, inlen);
  b2b_final(&s, buf);
  memcpy(out, buf, 32);
  uint32_t pos = 32, remaining = outlen - 32;
  while (remaining > 64) {
    blake2b(buf, 64, buf, 64);
    memcpy(out + pos, buf, 32);
    pos += 32;
    remaining -= 32;
  }
  blake2b(out + pos, remaining, buf, 64);
}

/* - Argon2 core - */

#define ARGON2_WORDS 128 /* 1024 bytes / 8 */
#define ARGON2_ADDR 128

static void P_perm(uint64_t *v) {
#define GB(a, b, c, d)                                                    \
  do {                                                                    \
    a = a + b + 2ULL * (uint64_t)((uint32_t)a) * (uint64_t)((uint32_t)b); \
    d = rotr64(d ^ a, 32);                                                \
    c = c + d + 2ULL * (uint64_t)((uint32_t)c) * (uint64_t)((uint32_t)d); \
    b = rotr64(b ^ c, 24);                                                \
    a = a + b + 2ULL * (uint64_t)((uint32_t)a) * (uint64_t)((uint32_t)b); \
    d = rotr64(d ^ a, 16);                                                \
    c = c + d + 2ULL * (uint64_t)((uint32_t)c) * (uint64_t)((uint32_t)d); \
    b = rotr64(b ^ c, 63);                                                \
  } while (0)
  GB(v[0], v[4], v[8], v[12]);
  GB(v[1], v[5], v[9], v[13]);
  GB(v[2], v[6], v[10], v[14]);
  GB(v[3], v[7], v[11], v[15]);
  GB(v[0], v[5], v[10], v[15]);
  GB(v[1], v[6], v[11], v[12]);
  GB(v[2], v[7], v[8], v[13]);
  GB(v[3], v[4], v[9], v[14]);
#undef GB
}

static void fill_block(const uint64_t *prev, const uint64_t *ref, uint64_t *next, int with_xor) {
  uint64_t R[ARGON2_WORDS], Z[ARGON2_WORDS], col[16];
  for (int i = 0; i < ARGON2_WORDS; i++) R[i] = prev[i] ^ ref[i];
  memcpy(Z, R, sizeof(R));
  for (int i = 0; i < 8; i++) P_perm(Z + 16 * i);
  for (int j = 0; j < 8; j++) {
    for (int r = 0; r < 8; r++) {
      col[2 * r] = Z[16 * r + 2 * j];
      col[2 * r + 1] = Z[16 * r + 2 * j + 1];
    }
    P_perm(col);
    for (int r = 0; r < 8; r++) {
      Z[16 * r + 2 * j] = col[2 * r];
      Z[16 * r + 2 * j + 1] = col[2 * r + 1];
    }
  }
  for (int i = 0; i < ARGON2_WORDS; i++) {
    uint64_t val = R[i] ^ Z[i];
    if (with_xor) val ^= next[i];
    next[i] = val;
  }
}

int eyas_argon2id(const uint8_t *pwd, size_t pwdlen, const uint8_t *salt, size_t saltlen,
                  const uint8_t *secret, size_t secretlen, const uint8_t *ad, size_t adlen,
                  uint32_t t, uint32_t m, uint32_t p, uint8_t *out, size_t outlen) {
  uint8_t h0[72], le[4]; /* H0 (64) + 8 bytes for block-index/lane */
  b2b_ctx s;
  uint64_t *mem = NULL;
  uint32_t mblocks, lane_len, seg_len;
  int ok = -1;

  if (p < 1 || t < 1 || m < 8 * p || outlen < 4 || outlen > 0xffffffffU) return -1;

  mblocks = 4 * p * (m / (4 * p));
  lane_len = mblocks / p;
  seg_len = lane_len / 4;

  /* H0 = BLAKE2b( p,outlen,m,t,version,type, len|pwd, len|salt, len|secret, len|ad ) */
  b2b_init(&s, 64);
  store32(le, p);
  b2b_update(&s, le, 4);
  store32(le, (uint32_t)outlen);
  b2b_update(&s, le, 4);
  store32(le, m);
  b2b_update(&s, le, 4);
  store32(le, t);
  b2b_update(&s, le, 4);
  store32(le, 0x13);
  b2b_update(&s, le, 4); /* version 1.3 */
  store32(le, 2);
  b2b_update(&s, le, 4); /* type Argon2id */
  store32(le, (uint32_t)pwdlen);
  b2b_update(&s, le, 4);
  b2b_update(&s, pwd, pwdlen);
  store32(le, (uint32_t)saltlen);
  b2b_update(&s, le, 4);
  b2b_update(&s, salt, saltlen);
  store32(le, (uint32_t)secretlen);
  b2b_update(&s, le, 4);
  if (secretlen) b2b_update(&s, secret, secretlen);
  store32(le, (uint32_t)adlen);
  b2b_update(&s, le, 4);
  if (adlen) b2b_update(&s, ad, adlen);
  b2b_final(&s, h0);

  mem = (uint64_t *)malloc((size_t)mblocks * ARGON2_WORDS * sizeof(uint64_t));
  if (!mem) return -1;

  /* First two blocks of every lane. */
  for (uint32_t lane = 0; lane < p; lane++) {
    uint8_t blk[1024];
    store32(h0 + 64, 0);
    store32(h0 + 68, lane);
    blake2b_long(blk, 1024, h0, 72);
    for (size_t w = 0; w < ARGON2_WORDS; w++) mem[(size_t)(lane * lane_len + 0) * ARGON2_WORDS + w] = load64(blk + 8 * w);
    store32(h0 + 64, 1);
    blake2b_long(blk, 1024, h0, 72);
    for (size_t w = 0; w < ARGON2_WORDS; w++) mem[(size_t)(lane * lane_len + 1) * ARGON2_WORDS + w] = load64(blk + 8 * w);
  }

  for (uint32_t pass = 0; pass < t; pass++) {
    for (uint32_t slice = 0; slice < 4; slice++) {
      for (uint32_t lane = 0; lane < p; lane++) {
        uint64_t addr[ARGON2_WORDS], input[ARGON2_WORDS], zero[ARGON2_WORDS];
        int data_indep = (pass == 0 && slice < 2);
        uint32_t start = (pass == 0 && slice == 0) ? 2 : 0;
        if (data_indep) {
          memset(zero, 0, sizeof(zero));
          memset(input, 0, sizeof(input));
          input[0] = pass;
          input[1] = lane;
          input[2] = slice;
          input[3] = mblocks;
          input[4] = t;
          input[5] = 2;
        }
        for (uint32_t idx = start; idx < seg_len; idx++) {
          uint32_t cur = lane * lane_len + slice * seg_len + idx;
          uint32_t prev = (cur % lane_len == 0) ? cur + lane_len - 1 : cur - 1;
          uint64_t rnd;
          if (data_indep) {
            if (idx % ARGON2_ADDR == 0 || idx == start) {
              input[6]++;
              fill_block(zero, input, addr, 0);
              fill_block(zero, addr, addr, 0);
            }
            rnd = addr[idx % ARGON2_ADDR];
          } else {
            rnd = mem[(size_t)prev * ARGON2_WORDS];
          }
          uint32_t ref_lane = (uint32_t)(rnd >> 32) % p;
          if (pass == 0 && slice == 0) ref_lane = lane;
          uint32_t j1 = (uint32_t)rnd;
          /* reference area size */
          uint32_t area;
          int same_lane = (ref_lane == lane);
          if (pass == 0) {
            if (slice == 0) area = idx - 1;
            else if (same_lane) area = slice * seg_len + idx - 1;
            else area = slice * seg_len + (idx == 0 ? (uint32_t)-1 : 0);
          } else {
            if (same_lane) area = lane_len - seg_len + idx - 1;
            else area = lane_len - seg_len + (idx == 0 ? (uint32_t)-1 : 0);
          }
          uint64_t rel = j1;
          rel = (rel * rel) >> 32;
          rel = area - 1 - ((area * rel) >> 32);
          uint32_t startpos = (pass != 0 && slice != 3) ? (slice + 1) * seg_len : 0;
          uint32_t ref_idx = (uint32_t)((startpos + rel) % lane_len);
          uint64_t *ref_block = mem + (size_t)(ref_lane * lane_len + ref_idx) * ARGON2_WORDS;
          uint64_t *cur_block = mem + (size_t)cur * ARGON2_WORDS;
          uint64_t *prev_block = mem + (size_t)prev * ARGON2_WORDS;
          fill_block(prev_block, ref_block, cur_block, pass != 0);
        }
      }
    }
  }

  /* Final block = XOR of the last block of every lane; tag = H'(final). */
  {
    uint64_t final[ARGON2_WORDS];
    uint8_t fb[1024];
    memcpy(final, mem + (size_t)(lane_len - 1) * ARGON2_WORDS, sizeof(final));
    for (uint32_t lane = 1; lane < p; lane++)
      for (size_t w = 0; w < ARGON2_WORDS; w++) final[w] ^= mem[(size_t)(lane * lane_len + lane_len - 1) * ARGON2_WORDS + w];
    for (size_t w = 0; w < ARGON2_WORDS; w++) store64(fb + 8 * w, final[w]);
    blake2b_long(out, (uint32_t)outlen, fb, 1024);
    ok = 0;
  }
  free(mem);
  return ok;
}
