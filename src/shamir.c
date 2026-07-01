#include "eyas_crypt.h"

#include <string.h>

/*
 * Shamir Secret Sharing over GF(2^8) with the AES reduction polynomial
 * 0x11b and generator 0x03. Each of the 32 secret bytes is shared
 * independently: a random degree (k-1) polynomial with the secret byte as
 * its constant term is evaluated at the distinct, non-zero x-coordinates
 * 1..n. Any k shares reconstruct the secret by Lagrange interpolation at
 * x = 0; any k-1 shares reveal nothing (information-theoretic secrecy).
 *
 * A share is 33 bytes: share[0] is the x-coordinate, share[1..32] are the
 * evaluated y-bytes of the 32 secret bytes.
 */

static uint8_t gf_exp[512];
static uint8_t gf_log[256];
static int gf_ready;

static uint8_t gf_mul_slow(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1U) p ^= a;
    uint8_t hi = (uint8_t)(a & 0x80U);
    a = (uint8_t)(a << 1);
    if (hi) a ^= 0x1bU;
    b = (uint8_t)(b >> 1);
  }
  return p;
}

static void gf_init(void) {
  uint8_t x = 1;
  for (int i = 0; i < 255; i++) {
    gf_exp[i] = x;
    gf_log[x] = (uint8_t)i;
    x = gf_mul_slow(x, 0x03U);
  }
  for (int i = 255; i < 512; i++) gf_exp[i] = gf_exp[i - 255];
  gf_log[0] = 0;
  gf_ready = 1;
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
  if (a == 0 || b == 0) return 0;
  return gf_exp[gf_log[a] + gf_log[b]];
}

static uint8_t gf_div(uint8_t a, uint8_t b) {
  if (a == 0) return 0;
  return gf_exp[gf_log[a] + (255 - gf_log[b])];
}

int eyas_shamir_split(const uint8_t secret[32], int k, int n, uint8_t *shares) {
  uint8_t coef[255]; /* degree k-1 polynomial: k coefficients, k <= n <= 255 */
  if (!gf_ready) gf_init();
  if (k < 2 || n < k || n > 255) return -1;
  for (int x = 1; x <= n; x++) {
    uint8_t *out = shares + (size_t)(x - 1) * 33;
    out[0] = (uint8_t)x;
    for (int b = 0; b < 32; b++) out[1 + b] = secret[b];
  }
  for (int b = 0; b < 32; b++) {
    coef[0] = secret[b];
    if (k > 1 && eyas_random(coef + 1, (size_t)(k - 1)) != 0) return -1;
    for (int x = 1; x <= n; x++) {
      uint8_t y = coef[0];
      uint8_t xp = (uint8_t)x;
      for (int d = 1; d < k; d++) {
        y ^= gf_mul(coef[d], xp);
        xp = gf_mul(xp, (uint8_t)x);
      }
      shares[(size_t)(x - 1) * 33 + 1 + (size_t)b] = y;
    }
  }
  return 0;
}

int eyas_shamir_combine(const uint8_t *shares, int count, uint8_t secret[32]) {
  if (!gf_ready) gf_init();
  if (count < 2) return -1;
  for (int i = 0; i < count; i++) {
    if (shares[(size_t)i * 33] == 0) return -1;
    for (int j = i + 1; j < count; j++)
      if (shares[(size_t)i * 33] == shares[(size_t)j * 33]) return -1;
  }
  for (int b = 0; b < 32; b++) {
    uint8_t acc = 0;
    for (int i = 0; i < count; i++) {
      uint8_t xi = shares[(size_t)i * 33];
      uint8_t yi = shares[(size_t)i * 33 + 1 + (size_t)b];
      uint8_t num = 1, den = 1;
      for (int j = 0; j < count; j++) {
        if (j == i) continue;
        uint8_t xj = shares[(size_t)j * 33];
        num = gf_mul(num, xj); /* (0 - xj) == xj in GF(2^8) */
        den = gf_mul(den, (uint8_t)(xi ^ xj));
      }
      acc ^= gf_mul(yi, gf_div(num, den));
    }
    secret[b] = acc;
  }
  return 0;
}
