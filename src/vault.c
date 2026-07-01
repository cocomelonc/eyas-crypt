#include "eyas_crypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#define EYAS_STDERR_TTY _isatty(_fileno(stderr))
#else
#include <sys/stat.h>
#include <unistd.h>
#define EYAS_STDERR_TTY isatty(2)
#endif

static int read_all(const char *path, uint8_t **data, size_t *len) {
  FILE *f = fopen(path, "rb");
  long n;
  if (!f) return -1;
  if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return -1;
  }
  *data = (uint8_t *)malloc((size_t)n);
  if ((size_t)n > 0 && !*data) {
    fclose(f);
    return -1;
  }
  if ((size_t)n > 0 && fread(*data, 1, (size_t)n, f) != (size_t)n) {
    free(*data);
    fclose(f);
    return -1;
  }
  fclose(f);
  *len = (size_t)n;
  return 0;
}

static int write_all(const char *path, const uint8_t *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f) return -1;
  if (len > 0 && fwrite(data, 1, len, f) != len) {
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static const char *base_name(const char *path) {
  const char *a = strrchr(path, '/');
  const char *b = strrchr(path, '\\');
  const char *p = a > b ? a : b;
  return p ? p + 1 : path;
}

static const char *g_open_device_path;

static void derive(const char *pass, const uint8_t salt[EYAS_SALT_LEN], uint32_t iters, uint8_t enc[32], uint8_t mac[32]) {
  uint8_t material[64];
  eyas_pbkdf2_sha256(pass, salt, EYAS_SALT_LEN, iters, material, sizeof(material));
  memcpy(enc, material, 32);
  memcpy(mac, material + 32, 32);
}

static void derive_data_keys(const uint8_t data_key[32], uint8_t enc[32], uint8_t mac[32]) {
  eyas_hmac_sha256(data_key, 32, (const uint8_t *)"eyas payload enc v2", 19, enc);
  eyas_hmac_sha256(data_key, 32, (const uint8_t *)"eyas payload mac v2", 19, mac);
}

static void device_id_from_secret(const uint8_t secret[32], char out[EYAS_HASH_HEX]) {
  eyas_sha256_hex(secret, 32, out);
}

static int read_device_secret(const char *path, uint8_t secret[32], char id[EYAS_HASH_HEX]) {
  uint8_t *buf = NULL, raw[32];
  size_t len = 0, raw_len = 0;
  char *s, *e;
  int ok = -1;
  if (read_all(path, &buf, &len) != 0) return -1;
  if (len < strlen("EYASDEVICE1")) goto out;
  s = strstr((char *)buf, "secret=");
  if (!s) goto out;
  s += 7;
  e = strchr(s, '\n');
  if (e) *e = '\0';
  if (eyas_hex_decode(s, raw, sizeof(raw), &raw_len) != 0 || raw_len != 32) goto out;
  memcpy(secret, raw, 32);
  device_id_from_secret(secret, id);
  ok = 0;
out:
  free(buf);
  return ok;
}

int eyas_device_enroll(const char *path) {
  uint8_t secret[32];
  char secret_hex[65], id[EYAS_HASH_HEX];
  FILE *f;
  if (eyas_random(secret, sizeof(secret)) != 0) return -1;
  eyas_hex_encode(secret, sizeof(secret), secret_hex);
  device_id_from_secret(secret, id);
  f = fopen(path, "wb");
  if (!f) return -1;
  fprintf(f, "EYASDEVICE1\nid=%s\nsecret=%s\n", id, secret_hex);
  fclose(f);
#ifndef _WIN32
  chmod(path, S_IRUSR | S_IWUSR);
#endif
  return 0;
}

int eyas_device_id(const char *path, char out[EYAS_HASH_HEX]) {
  uint8_t secret[32];
  return read_device_secret(path, secret, out);
}

static void wrap_key(const char *pass, const uint8_t salt[EYAS_SALT_LEN], uint32_t iters, const uint8_t device_secret[32], const uint8_t wrap_nonce[12], const uint8_t data_key[32], uint8_t wrapped[32]) {
  uint8_t pass_key[32], dev_key[32], mix[76], kek[32], stream[32];
  eyas_pbkdf2_sha256(pass, salt, EYAS_SALT_LEN, iters, pass_key, sizeof(pass_key));
  eyas_hmac_sha256(device_secret, 32, (const uint8_t *)"eyas device key v1", 18, dev_key);
  memcpy(mix, pass_key, 32);
  memcpy(mix + 32, dev_key, 32);
  memcpy(mix + 64, wrap_nonce, 12);
  eyas_sha256(mix, sizeof(mix), kek);
  eyas_hmac_sha256(kek, 32, (const uint8_t *)"eyas wrap stream v1", 19, stream);
  for (size_t i = 0; i < 32; i++) wrapped[i] = (uint8_t)(data_key[i] ^ stream[i]);
}

static void unwrap_key(const char *pass, const uint8_t salt[EYAS_SALT_LEN], uint32_t iters, const uint8_t device_secret[32], const uint8_t wrap_nonce[12], const uint8_t wrapped[32], uint8_t data_key[32]) {
  wrap_key(pass, salt, iters, device_secret, wrap_nonce, wrapped, data_key);
}

/* A minimal ASCII progress bar on stderr, cyan when interactive. */
static void progress_bar(const char *label, unsigned long long done, unsigned long long total) {
  int width = 24, fill, i;
  double f = total ? (double)done / (double)total : 1.0;
  if (f > 1.0) f = 1.0;
  fill = (int)(f * width);
  fprintf(stderr, "\r  %-9s [\033[36m", label);
  for (i = 0; i < fill; i++) fputc('#', stderr);
  fprintf(stderr, "\033[0m");
  for (i = fill; i < width; i++) fputc('-', stderr);
  fprintf(stderr, "] %3d%%", (int)(f * 100.0 + 0.5));
  fflush(stderr);
}

/* Time-lock factor: SHA-256 applied to itself `steps` times. The chain is
   inherently sequential (each hash depends on the previous), so it cannot be
   parallelized across cores or GPUs - the only way to unlock is to spend the
   wall-clock time. seed and steps are public; the chain output is the secret.
   When `label` is set and stderr is a terminal, a progress bar is drawn. */
static void timelock_chain(const uint8_t seed[32], unsigned long long steps, uint8_t out[32], const char *label) {
  uint8_t cur[32];
  unsigned long long done = 0, chunk = steps / 100;
  int show = label && EYAS_STDERR_TTY;
  if (chunk == 0) chunk = 1;
  memcpy(cur, seed, 32);
  while (done < steps) {
    unsigned long long n = steps - done < chunk ? steps - done : chunk;
    for (unsigned long long j = 0; j < n; j++) eyas_sha256(cur, 32, cur);
    done += n;
    if (show) progress_bar(label, done, steps);
  }
  if (show) fputc('\n', stderr);
  memcpy(out, cur, 32);
}

/* Estimate how many sequential SHA-256 steps approximate `seconds` of work on
   this machine, via a short calibration burst. */
static unsigned long long timelock_calibrate(double seconds) {
  uint8_t b[32] = {0};
  unsigned long long n = 0;
  clock_t t0 = clock();
  while ((double)(clock() - t0) / CLOCKS_PER_SEC < 0.05) {
    for (int i = 0; i < 4096; i++) eyas_sha256(b, 32, b);
    n += 4096;
  }
  double rate = (double)n / ((double)(clock() - t0) / CLOCKS_PER_SEC);
  unsigned long long steps = (unsigned long long)(rate * seconds);
  return steps < 1 ? 1 : steps;
}

static int read_line(FILE *f, char *out, size_t out_len) {
  int c;
  size_t i = 0;
  while ((c = fgetc(f)) != EOF) {
    if (c == '\n') break;
    if (c != '\r' && i + 1 < out_len) out[i++] = (char)c;
  }
  out[i] = '\0';
  return c == EOF && i == 0 ? -1 : 0;
}

static int copy_value(char *dst, size_t dst_len, const char *line, const char *key) {
  size_t k = strlen(key), n;
  if (strncmp(line, key, k) != 0 || line[k] != '=') return 0;
  n = strlen(line + k + 1);
  if (n + 1 > dst_len) return -1;
  memcpy(dst, line + k + 1, n + 1);
  return 1;
}

typedef struct {
  int version;
  uint32_t iter;
  char salt[40];
  char nonce[32];
  char size[32];
  char tag[80];
  char device_id[80];
  char wrap_nonce[32];
  char wrapped_key[80];
  char group_id[80];
  int threshold;
  int shares;
  char timelock_seed[80];
  unsigned long long timelock_steps;
  int recipients;
  char kdf[24];
  uint32_t a_m, a_t, a_p;
  char header[2048];
  size_t header_len;
} vault_header;

static int parse_header(FILE *f, vault_header *h) {
  char line[256];
  memset(h, 0, sizeof(*h));
  if (read_line(f, line, sizeof(line)) != 0 || strcmp(line, EYAS_VAULT_MAGIC) != 0) return -1;
  h->header_len += (size_t)snprintf(h->header + h->header_len, sizeof(h->header) - h->header_len, "%s\n", line);
  while (read_line(f, line, sizeof(line)) == 0) {
    int r;
    if (line[0] == '\0') break;
    r = copy_value(h->tag, sizeof(h->tag), line, "tag");
    if (r < 0) return -1;
    if (r == 1) continue;
    if (h->header_len + strlen(line) + 2 >= sizeof(h->header)) return -1;
    h->header_len += (size_t)snprintf(h->header + h->header_len, sizeof(h->header) - h->header_len, "%s\n", line);
    if ((r = copy_value(h->salt, sizeof(h->salt), line, "salt")) < 0) return -1;
    if ((r = copy_value(h->nonce, sizeof(h->nonce), line, "nonce")) < 0) return -1;
    if ((r = copy_value(h->size, sizeof(h->size), line, "size")) < 0) return -1;
    if ((r = copy_value(h->device_id, sizeof(h->device_id), line, "device_id")) < 0) return -1;
    if ((r = copy_value(h->wrap_nonce, sizeof(h->wrap_nonce), line, "wrap_nonce")) < 0) return -1;
    if ((r = copy_value(h->wrapped_key, sizeof(h->wrapped_key), line, "wrapped_key")) < 0) return -1;
    if ((r = copy_value(h->group_id, sizeof(h->group_id), line, "group_id")) < 0) return -1;
    if ((r = copy_value(h->timelock_seed, sizeof(h->timelock_seed), line, "timelock_seed")) < 0) return -1;
    if (strncmp(line, "version=", 8) == 0) h->version = atoi(line + 8);
    if (strncmp(line, "iter=", 5) == 0) h->iter = (uint32_t)strtoul(line + 5, NULL, 10);
    if (strncmp(line, "threshold=", 10) == 0) h->threshold = atoi(line + 10);
    if (strncmp(line, "shares=", 7) == 0) h->shares = atoi(line + 7);
    if (strncmp(line, "timelock_steps=", 15) == 0) h->timelock_steps = strtoull(line + 15, NULL, 10);
    if (strncmp(line, "recipients=", 11) == 0) h->recipients = atoi(line + 11);
    if ((r = copy_value(h->kdf, sizeof(h->kdf), line, "kdf")) < 0) return -1;
    if (strncmp(line, "argon2_m=", 9) == 0) h->a_m = (uint32_t)strtoul(line + 9, NULL, 10);
    if (strncmp(line, "argon2_t=", 9) == 0) h->a_t = (uint32_t)strtoul(line + 9, NULL, 10);
    if (strncmp(line, "argon2_p=", 9) == 0) h->a_p = (uint32_t)strtoul(line + 9, NULL, 10);
  }
  if (!h->version) h->version = 1;
  if (!(h->nonce[0] && h->size[0] && h->tag[0])) return -1;
  if (h->version != 6 && !h->iter) return -1;    /* v6 uses Argon2 m/t/p instead of iter */
  if (h->version <= 4 && !h->salt[0]) return -1; /* per-recipient salts live in slot lines for v5 */
  if (h->version == 6 && !(h->salt[0] && h->a_m && h->a_t && h->a_p)) return -1;
  if (h->version == 2 && !(h->device_id[0] && h->wrap_nonce[0] && h->wrapped_key[0])) return -1;
  if (h->version == 3 && !(h->group_id[0] && h->wrap_nonce[0] && h->wrapped_key[0] && h->threshold >= 2 && h->shares >= h->threshold)) return -1;
  if (h->version == 4 && !(h->timelock_seed[0] && h->timelock_steps && h->wrap_nonce[0] && h->wrapped_key[0])) return -1;
  if (h->version == 5 && h->recipients < 1) return -1;
  return 0;
}

int eyas_vault_seal_memory(const uint8_t *plain, size_t plain_len, const char *name, const char *pass, uint32_t iters, uint8_t **out_buf, size_t *out_len) {
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], enc_key[32], mac_key[32], mac[EYAS_MAC_LEN];
  char salt_hex[EYAS_SALT_LEN * 2 + 1], nonce_hex[EYAS_NONCE_LEN * 2 + 1], mac_hex[EYAS_MAC_LEN * 2 + 1];
  uint8_t *payload = NULL, *mac_input = NULL;
  size_t name_len, payload_len, header_len, tag_len, total_len;
  char header[1024];
  int ok = -1;

  if (!pass || !*pass || iters < 10000U) return -1;
  name_len = strlen(name ? name : "file");
  if (name_len > 255) goto out;
  payload_len = 2 + name_len + plain_len;
  payload = (uint8_t *)malloc(payload_len);
  if (!payload) goto out;
  payload[0] = (uint8_t)(name_len >> 8);
  payload[1] = (uint8_t)name_len;
  memcpy(payload + 2, name ? name : "file", name_len);
  memcpy(payload + 2 + name_len, plain, plain_len);

  if (eyas_random(salt, sizeof(salt)) != 0 || eyas_random(nonce, sizeof(nonce)) != 0) goto out;
  derive(pass, salt, iters, enc_key, mac_key);
  eyas_chacha20_xor(payload, payload_len, enc_key, nonce);
  eyas_hex_encode(salt, sizeof(salt), salt_hex);
  eyas_hex_encode(nonce, sizeof(nonce), nonce_hex);

  header_len = (size_t)snprintf(header, sizeof(header),
                                EYAS_VAULT_MAGIC "\n"
                                                 "version=1\n"
                                                 "cipher=chacha20\n"
                                                 "mac=hmac-sha256\n"
                                                 "kdf=pbkdf2-sha256\n"
                                                 "iter=%u\n"
                                                 "salt=%s\n"
                                                 "nonce=%s\n"
                                                 "size=%zu\n",
                                iters, salt_hex, nonce_hex, payload_len);
  if (header_len >= sizeof(header)) goto out;
  mac_input = (uint8_t *)malloc(header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, header, header_len);
  memcpy(mac_input + header_len, payload, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, header_len + payload_len, mac);
  eyas_hex_encode(mac, sizeof(mac), mac_hex);

  tag_len = strlen("tag=\n\n") + strlen(mac_hex);
  total_len = header_len + tag_len + payload_len;
  *out_buf = (uint8_t *)malloc(total_len);
  if (!*out_buf) goto out;
  memcpy(*out_buf, header, header_len);
  snprintf((char *)*out_buf + header_len, tag_len + 1, "tag=%s\n\n", mac_hex);
  memcpy(*out_buf + header_len + tag_len, payload, payload_len);
  *out_len = total_len;
  ok = 0;
out:
  free(payload);
  free(mac_input);
  return ok;
}

static int vault_seal_memory_device(const uint8_t *plain, size_t plain_len, const char *name, const char *pass, uint32_t iters, const uint8_t device_secret[32], const char device_id[EYAS_HASH_HEX], uint8_t **out_buf, size_t *out_len) {
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], wrap_nonce[EYAS_NONCE_LEN], data_key[32], enc_key[32], mac_key[32], wrapped[32], mac[EYAS_MAC_LEN];
  char salt_hex[33], nonce_hex[25], wrap_nonce_hex[25], wrapped_hex[65], mac_hex[65];
  uint8_t *payload = NULL, *mac_input = NULL;
  size_t name_len, payload_len, header_len, tag_len, total_len;
  char header[1400];
  int ok = -1;

  if (!pass || !*pass || iters < 10000U) return -1;
  name_len = strlen(name ? name : "file");
  if (name_len > 255) goto out;
  payload_len = 2 + name_len + plain_len;
  payload = (uint8_t *)malloc(payload_len);
  if (!payload) goto out;
  payload[0] = (uint8_t)(name_len >> 8);
  payload[1] = (uint8_t)name_len;
  memcpy(payload + 2, name ? name : "file", name_len);
  memcpy(payload + 2 + name_len, plain, plain_len);
  if (eyas_random(salt, sizeof(salt)) != 0 || eyas_random(nonce, sizeof(nonce)) != 0 ||
      eyas_random(wrap_nonce, sizeof(wrap_nonce)) != 0 || eyas_random(data_key, sizeof(data_key)) != 0) goto out;
  derive_data_keys(data_key, enc_key, mac_key);
  eyas_chacha20_xor(payload, payload_len, enc_key, nonce);
  wrap_key(pass, salt, iters, device_secret, wrap_nonce, data_key, wrapped);
  eyas_hex_encode(salt, sizeof(salt), salt_hex);
  eyas_hex_encode(nonce, sizeof(nonce), nonce_hex);
  eyas_hex_encode(wrap_nonce, sizeof(wrap_nonce), wrap_nonce_hex);
  eyas_hex_encode(wrapped, sizeof(wrapped), wrapped_hex);
  header_len = (size_t)snprintf(header, sizeof(header),
                                EYAS_VAULT_MAGIC "\n"
                                                 "version=2\n"
                                                 "cipher=chacha20\n"
                                                 "mac=hmac-sha256\n"
                                                 "kdf=pbkdf2-sha256\n"
                                                 "policy=passphrase+device-key\n"
                                                 "iter=%u\n"
                                                 "salt=%s\n"
                                                 "nonce=%s\n"
                                                 "size=%zu\n"
                                                 "device_id=%s\n"
                                                 "wrap_nonce=%s\n"
                                                 "wrapped_key=%s\n",
                                iters, salt_hex, nonce_hex, payload_len, device_id, wrap_nonce_hex, wrapped_hex);
  if (header_len >= sizeof(header)) goto out;
  mac_input = (uint8_t *)malloc(header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, header, header_len);
  memcpy(mac_input + header_len, payload, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, header_len + payload_len, mac);
  eyas_hex_encode(mac, sizeof(mac), mac_hex);
  tag_len = strlen("tag=\n\n") + strlen(mac_hex);
  total_len = header_len + tag_len + payload_len;
  *out_buf = (uint8_t *)malloc(total_len);
  if (!*out_buf) goto out;
  memcpy(*out_buf, header, header_len);
  snprintf((char *)*out_buf + header_len, tag_len + 1, "tag=%s\n\n", mac_hex);
  memcpy(*out_buf + header_len + tag_len, payload, payload_len);
  *out_len = total_len;
  ok = 0;
out:
  free(payload);
  free(mac_input);
  return ok;
}

int eyas_vault_seal_threshold_memory(const uint8_t *plain, size_t plain_len, const char *name, const char *pass, uint32_t iters, int k, int n, uint8_t **out_buf, size_t *out_len, uint8_t *shares, char group_id[EYAS_HASH_HEX]) {
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], wrap_nonce[EYAS_NONCE_LEN], group_secret[32], data_key[32], enc_key[32], mac_key[32], wrapped[32], mac[EYAS_MAC_LEN];
  char salt_hex[33], nonce_hex[25], wrap_nonce_hex[25], wrapped_hex[65], mac_hex[65];
  uint8_t *payload = NULL, *mac_input = NULL;
  size_t name_len, payload_len, header_len, tag_len, total_len;
  char header[1400];
  int ok = -1;

  if (!pass || !*pass || iters < 10000U) return -1;
  if (k < 2 || n < k || n > 255) return -1;
  name_len = strlen(name ? name : "file");
  if (name_len > 255) goto out;
  payload_len = 2 + name_len + plain_len;
  payload = (uint8_t *)malloc(payload_len);
  if (!payload) goto out;
  payload[0] = (uint8_t)(name_len >> 8);
  payload[1] = (uint8_t)name_len;
  memcpy(payload + 2, name ? name : "file", name_len);
  memcpy(payload + 2 + name_len, plain, plain_len);
  if (eyas_random(salt, sizeof(salt)) != 0 || eyas_random(nonce, sizeof(nonce)) != 0 ||
      eyas_random(wrap_nonce, sizeof(wrap_nonce)) != 0 || eyas_random(data_key, sizeof(data_key)) != 0 ||
      eyas_random(group_secret, sizeof(group_secret)) != 0) goto out;
  if (eyas_shamir_split(group_secret, k, n, shares) != 0) goto out;
  device_id_from_secret(group_secret, group_id);
  derive_data_keys(data_key, enc_key, mac_key);
  eyas_chacha20_xor(payload, payload_len, enc_key, nonce);
  wrap_key(pass, salt, iters, group_secret, wrap_nonce, data_key, wrapped);
  eyas_hex_encode(salt, sizeof(salt), salt_hex);
  eyas_hex_encode(nonce, sizeof(nonce), nonce_hex);
  eyas_hex_encode(wrap_nonce, sizeof(wrap_nonce), wrap_nonce_hex);
  eyas_hex_encode(wrapped, sizeof(wrapped), wrapped_hex);
  header_len = (size_t)snprintf(header, sizeof(header),
                                EYAS_VAULT_MAGIC "\n"
                                                 "version=3\n"
                                                 "cipher=chacha20\n"
                                                 "mac=hmac-sha256\n"
                                                 "kdf=pbkdf2-sha256\n"
                                                 "policy=passphrase+threshold\n"
                                                 "iter=%u\n"
                                                 "salt=%s\n"
                                                 "nonce=%s\n"
                                                 "size=%zu\n"
                                                 "group_id=%s\n"
                                                 "threshold=%d\n"
                                                 "shares=%d\n"
                                                 "wrap_nonce=%s\n"
                                                 "wrapped_key=%s\n",
                                iters, salt_hex, nonce_hex, payload_len, group_id, k, n, wrap_nonce_hex, wrapped_hex);
  if (header_len >= sizeof(header)) goto out;
  mac_input = (uint8_t *)malloc(header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, header, header_len);
  memcpy(mac_input + header_len, payload, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, header_len + payload_len, mac);
  eyas_hex_encode(mac, sizeof(mac), mac_hex);
  tag_len = strlen("tag=\n\n") + strlen(mac_hex);
  total_len = header_len + tag_len + payload_len;
  *out_buf = (uint8_t *)malloc(total_len);
  if (!*out_buf) goto out;
  memcpy(*out_buf, header, header_len);
  snprintf((char *)*out_buf + header_len, tag_len + 1, "tag=%s\n\n", mac_hex);
  memcpy(*out_buf + header_len + tag_len, payload, payload_len);
  *out_len = total_len;
  ok = 0;
out:
  free(payload);
  free(mac_input);
  return ok;
}

int eyas_vault_open_threshold_memory(const uint8_t *vault, size_t vault_len, const char *pass, const uint8_t *shares, int count, uint8_t **out_buf, size_t *out_len, char *name, size_t name_cap) {
  FILE *f = NULL;
  vault_header h;
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], got[EYAS_MAC_LEN], want[EYAS_MAC_LEN], enc_key[32], mac_key[32];
  uint8_t group_secret[32], wrap_nonce[EYAS_NONCE_LEN], wrapped[32], data_key[32];
  char got_group_id[EYAS_HASH_HEX];
  uint8_t *cipher = NULL, *mac_input = NULL;
  size_t n = 0, payload_len, salt_n = 0, nonce_n = 0, tag_n = 0, wrap_nonce_n = 0, wrapped_n = 0, name_len;
  int ok = -1;

  if (!pass || !*pass) return -1;
  f = tmpfile();
  if (!f) return -1;
  if (vault_len > 0 && fwrite(vault, 1, vault_len, f) != vault_len) goto out;
  rewind(f);
  if (parse_header(f, &h) != 0 || h.version != 3) goto out;
  if (count < h.threshold) goto out;
  if (eyas_shamir_combine(shares, count, group_secret) != 0) goto out;
  device_id_from_secret(group_secret, got_group_id);
  if (strcmp(got_group_id, h.group_id) != 0) goto out;
  payload_len = (size_t)strtoull(h.size, NULL, 10);
  if (payload_len < 2) goto out;
  cipher = (uint8_t *)malloc(payload_len);
  if (!cipher) goto out;
  n = fread(cipher, 1, payload_len, f);
  if (n != payload_len) goto out;
  if (eyas_hex_decode(h.salt, salt, sizeof(salt), &salt_n) != 0 || salt_n != EYAS_SALT_LEN) goto out;
  if (eyas_hex_decode(h.nonce, nonce, sizeof(nonce), &nonce_n) != 0 || nonce_n != EYAS_NONCE_LEN) goto out;
  if (eyas_hex_decode(h.tag, got, sizeof(got), &tag_n) != 0 || tag_n != EYAS_MAC_LEN) goto out;
  if (eyas_hex_decode(h.wrap_nonce, wrap_nonce, sizeof(wrap_nonce), &wrap_nonce_n) != 0 || wrap_nonce_n != EYAS_NONCE_LEN) goto out;
  if (eyas_hex_decode(h.wrapped_key, wrapped, sizeof(wrapped), &wrapped_n) != 0 || wrapped_n != 32) goto out;
  unwrap_key(pass, salt, h.iter, group_secret, wrap_nonce, wrapped, data_key);
  derive_data_keys(data_key, enc_key, mac_key);
  mac_input = (uint8_t *)malloc(h.header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, h.header, h.header_len);
  memcpy(mac_input + h.header_len, cipher, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, h.header_len + payload_len, want);
  if (!eyas_ct_eq(got, want, EYAS_MAC_LEN)) goto out;
  eyas_chacha20_xor(cipher, payload_len, enc_key, nonce);
  name_len = ((size_t)cipher[0] << 8) | cipher[1];
  if (name_len + 2 > payload_len) goto out;
  if (name && name_cap > 0) {
    size_t c = name_len + 1 > name_cap ? name_cap - 1 : name_len;
    memcpy(name, cipher + 2, c);
    name[c] = '\0';
  }
  *out_len = payload_len - 2 - name_len;
  *out_buf = (uint8_t *)malloc(*out_len);
  if (*out_len > 0 && !*out_buf) goto out;
  memcpy(*out_buf, cipher + 2 + name_len, *out_len);
  ok = 0;
out:
  if (f) fclose(f);
  free(cipher);
  free(mac_input);
  return ok;
}

static int write_share_file(const char *path, const char *group_id, int k, int n, const uint8_t share[33]) {
  char share_hex[65];
  FILE *f = fopen(path, "wb");
  if (!f) return -1;
  eyas_hex_encode(share + 1, 32, share_hex);
  fprintf(f, "EYASSHARE1\ngroup_id=%s\nthreshold=%d\nshares=%d\nindex=%u\nshare=%s\n",
          group_id, k, n, share[0], share_hex);
  fclose(f);
  return 0;
}

static int read_share_file(const char *path, uint8_t share[33], char group_id[EYAS_HASH_HEX]) {
  uint8_t *buf = NULL;
  size_t len = 0, raw_len = 0;
  char *p, *e;
  int idx = -1, ok = -1;
  if (read_all(path, &buf, &len) != 0) return -1;
  if (len < strlen("EYASSHARE1") || memcmp(buf, "EYASSHARE1", 10) != 0) goto out;
  p = strstr((char *)buf, "index=");
  if (!p) goto out;
  idx = atoi(p + 6);
  if (idx < 1 || idx > 255) goto out;
  p = strstr((char *)buf, "group_id=");
  if (!p) goto out;
  p += 9;
  e = strchr(p, '\n');
  if (e) {
    size_t gl = (size_t)(e - p);
    if (gl >= EYAS_HASH_HEX) goto out;
    memcpy(group_id, p, gl);
    group_id[gl] = '\0';
  }
  p = strstr((char *)buf, "share=");
  if (!p) goto out;
  p += 6;
  e = strchr(p, '\n');
  if (e) *e = '\0';
  if (eyas_hex_decode(p, share + 1, 32, &raw_len) != 0 || raw_len != 32) goto out;
  share[0] = (uint8_t)idx;
  ok = 0;
out:
  free(buf);
  return ok;
}

int eyas_vault_seal_threshold_file(const char *in_path, const char *out_path, const char *pass, uint32_t iters, int k, int n) {
  uint8_t *plain = NULL, *vault = NULL, *shares = NULL;
  size_t plain_len = 0, vault_len = 0;
  char group_id[EYAS_HASH_HEX];
  int ok = -1;
  if (k < 2 || n < k || n > 255) return -1;
  shares = (uint8_t *)malloc((size_t)n * 33);
  if (!shares) return -1;
  if (read_all(in_path, &plain, &plain_len) != 0) goto out;
  if (eyas_vault_seal_threshold_memory(plain, plain_len, base_name(in_path), pass, iters, k, n, &vault, &vault_len, shares, group_id) != 0) goto out;
  if (write_all(out_path, vault, vault_len) != 0) goto out;
  for (int i = 0; i < n; i++) {
    char share_path[EYAS_MAX_PATH];
    snprintf(share_path, sizeof(share_path), "%s.share%d", out_path, i + 1);
    if (write_share_file(share_path, group_id, k, n, shares + (size_t)i * 33) != 0) goto out;
    printf("share %d/%d -> %s\n", i + 1, n, share_path);
  }
  ok = 0;
out:
  free(plain);
  free(vault);
  free(shares);
  return ok;
}

int eyas_vault_open_threshold_file(const char *in_path, const char *out_path, const char *pass, const char **share_paths, int count) {
  uint8_t *vault = NULL, *plain = NULL, *shares = NULL;
  size_t vault_len = 0, plain_len = 0;
  char name[256];
  int ok = -1;
  if (count < 2) return -1;
  shares = (uint8_t *)malloc((size_t)count * 33);
  if (!shares) return -1;
  for (int i = 0; i < count; i++) {
    char gid[EYAS_HASH_HEX];
    if (read_share_file(share_paths[i], shares + (size_t)i * 33, gid) != 0) goto out;
  }
  if (read_all(in_path, &vault, &vault_len) != 0) goto out;
  if (eyas_vault_open_threshold_memory(vault, vault_len, pass, shares, count, &plain, &plain_len, name, sizeof(name)) != 0) goto out;
  ok = write_all(out_path, plain, plain_len);
out:
  free(vault);
  free(plain);
  free(shares);
  return ok;
}

int eyas_vault_seal_timelock_file(const char *in_path, const char *out_path, const char *pass, uint32_t iters, double seconds) {
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], wrap_nonce[EYAS_NONCE_LEN], seed[32], tl[32], data_key[32], enc_key[32], mac_key[32], wrapped[32], mac[EYAS_MAC_LEN];
  char salt_hex[33], nonce_hex[25], wrap_nonce_hex[25], wrapped_hex[65], mac_hex[65], seed_hex[65];
  uint8_t *plain = NULL, *payload = NULL, *mac_input = NULL, *vault = NULL;
  size_t plain_len = 0, name_len, payload_len, header_len, tag_len, total_len;
  unsigned long long steps;
  char header[1400];
  const char *name;
  int ok = -1;

  if (!pass || !*pass || iters < 10000U || seconds <= 0) return -1;
  if (read_all(in_path, &plain, &plain_len) != 0) return -1;
  name = base_name(in_path);
  name_len = strlen(name);
  if (name_len > 255) goto out;
  steps = timelock_calibrate(seconds);
  payload_len = 2 + name_len + plain_len;
  payload = (uint8_t *)malloc(payload_len);
  if (!payload) goto out;
  payload[0] = (uint8_t)(name_len >> 8);
  payload[1] = (uint8_t)name_len;
  memcpy(payload + 2, name, name_len);
  memcpy(payload + 2 + name_len, plain, plain_len);
  if (eyas_random(salt, sizeof(salt)) != 0 || eyas_random(nonce, sizeof(nonce)) != 0 ||
      eyas_random(wrap_nonce, sizeof(wrap_nonce)) != 0 || eyas_random(data_key, sizeof(data_key)) != 0 ||
      eyas_random(seed, sizeof(seed)) != 0) goto out;
  timelock_chain(seed, steps, tl, "locking");
  derive_data_keys(data_key, enc_key, mac_key);
  eyas_chacha20_xor(payload, payload_len, enc_key, nonce);
  wrap_key(pass, salt, iters, tl, wrap_nonce, data_key, wrapped);
  eyas_hex_encode(salt, sizeof(salt), salt_hex);
  eyas_hex_encode(nonce, sizeof(nonce), nonce_hex);
  eyas_hex_encode(wrap_nonce, sizeof(wrap_nonce), wrap_nonce_hex);
  eyas_hex_encode(wrapped, sizeof(wrapped), wrapped_hex);
  eyas_hex_encode(seed, sizeof(seed), seed_hex);
  header_len = (size_t)snprintf(header, sizeof(header),
                                EYAS_VAULT_MAGIC "\n"
                                                 "version=4\n"
                                                 "cipher=chacha20\n"
                                                 "mac=hmac-sha256\n"
                                                 "kdf=pbkdf2-sha256\n"
                                                 "policy=passphrase+timelock\n"
                                                 "iter=%u\n"
                                                 "salt=%s\n"
                                                 "nonce=%s\n"
                                                 "size=%zu\n"
                                                 "timelock_seed=%s\n"
                                                 "timelock_steps=%llu\n"
                                                 "wrap_nonce=%s\n"
                                                 "wrapped_key=%s\n",
                                iters, salt_hex, nonce_hex, payload_len, seed_hex, steps, wrap_nonce_hex, wrapped_hex);
  if (header_len >= sizeof(header)) goto out;
  mac_input = (uint8_t *)malloc(header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, header, header_len);
  memcpy(mac_input + header_len, payload, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, header_len + payload_len, mac);
  eyas_hex_encode(mac, sizeof(mac), mac_hex);
  tag_len = strlen("tag=\n\n") + strlen(mac_hex);
  total_len = header_len + tag_len + payload_len;
  vault = (uint8_t *)malloc(total_len);
  if (!vault) goto out;
  memcpy(vault, header, header_len);
  snprintf((char *)vault + header_len, tag_len + 1, "tag=%s\n\n", mac_hex);
  memcpy(vault + header_len + tag_len, payload, payload_len);
  ok = write_all(out_path, vault, total_len);
  if (ok == 0) printf("timelock: %llu sequential SHA-256 steps (~%.0fs to unlock)\n", steps, seconds);
out:
  free(plain);
  free(payload);
  free(mac_input);
  free(vault);
  return ok;
}

int eyas_vault_open_timelock_file(const char *in_path, const char *out_path, const char *pass) {
  FILE *f = NULL;
  vault_header h;
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], got[EYAS_MAC_LEN], want[EYAS_MAC_LEN], enc_key[32], mac_key[32];
  uint8_t seed[32], tl[32], wrap_nonce[EYAS_NONCE_LEN], wrapped[32], data_key[32];
  uint8_t *vault = NULL, *cipher = NULL, *mac_input = NULL, *plain = NULL;
  size_t vault_len = 0, payload_len, salt_n = 0, nonce_n = 0, tag_n = 0, wrap_nonce_n = 0, wrapped_n = 0, seed_n = 0, name_len, plain_len;
  char name[256];
  int ok = -1;

  if (!pass || !*pass) return -1;
  if (read_all(in_path, &vault, &vault_len) != 0) return -1;
  f = tmpfile();
  if (!f) goto out;
  if (vault_len > 0 && fwrite(vault, 1, vault_len, f) != vault_len) goto out;
  rewind(f);
  if (parse_header(f, &h) != 0 || h.version != 4) goto out;
  payload_len = (size_t)strtoull(h.size, NULL, 10);
  if (payload_len < 2) goto out;
  cipher = (uint8_t *)malloc(payload_len);
  if (!cipher) goto out;
  if (fread(cipher, 1, payload_len, f) != payload_len) goto out;
  if (eyas_hex_decode(h.salt, salt, sizeof(salt), &salt_n) != 0 || salt_n != EYAS_SALT_LEN) goto out;
  if (eyas_hex_decode(h.nonce, nonce, sizeof(nonce), &nonce_n) != 0 || nonce_n != EYAS_NONCE_LEN) goto out;
  if (eyas_hex_decode(h.tag, got, sizeof(got), &tag_n) != 0 || tag_n != EYAS_MAC_LEN) goto out;
  if (eyas_hex_decode(h.wrap_nonce, wrap_nonce, sizeof(wrap_nonce), &wrap_nonce_n) != 0 || wrap_nonce_n != EYAS_NONCE_LEN) goto out;
  if (eyas_hex_decode(h.wrapped_key, wrapped, sizeof(wrapped), &wrapped_n) != 0 || wrapped_n != 32) goto out;
  if (eyas_hex_decode(h.timelock_seed, seed, sizeof(seed), &seed_n) != 0 || seed_n != 32) goto out;
  timelock_chain(seed, h.timelock_steps, tl, "unlocking"); /* the unavoidable sequential work */
  unwrap_key(pass, salt, h.iter, tl, wrap_nonce, wrapped, data_key);
  derive_data_keys(data_key, enc_key, mac_key);
  mac_input = (uint8_t *)malloc(h.header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, h.header, h.header_len);
  memcpy(mac_input + h.header_len, cipher, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, h.header_len + payload_len, want);
  if (!eyas_ct_eq(got, want, EYAS_MAC_LEN)) goto out;
  eyas_chacha20_xor(cipher, payload_len, enc_key, nonce);
  name_len = ((size_t)cipher[0] << 8) | cipher[1];
  if (name_len + 2 > payload_len) goto out;
  plain_len = payload_len - 2 - name_len;
  plain = (uint8_t *)malloc(plain_len ? plain_len : 1);
  if (!plain) goto out;
  memcpy(plain, cipher + 2 + name_len, plain_len);
  (void)name;
  ok = write_all(out_path, plain, plain_len);
out:
  if (f) fclose(f);
  free(vault);
  free(cipher);
  free(mac_input);
  free(plain);
  return ok;
}

/* Multi-recipient: the payload data key is wrapped once per recipient
   passphrase into an independent slot. Any single recipient opens the vault
   with only their own passphrase; recipients never learn each other's. */
int eyas_vault_seal_multi_file(const char *in_path, const char *out_path, const char **passes, int count, uint32_t iters) {
  uint8_t nonce[EYAS_NONCE_LEN], data_key[32], enc_key[32], mac_key[32], mac[EYAS_MAC_LEN];
  const uint8_t zero[32] = {0};
  char nonce_hex[25], mac_hex[65];
  uint8_t *plain = NULL, *payload = NULL, *mac_input = NULL, *vault = NULL;
  size_t plain_len = 0, name_len, payload_len, header_len = 0, tag_len, total_len, cap;
  char *header = NULL;
  const char *name;
  int ok = -1;

  if (count < 1 || count > 64 || iters < 10000U) return -1;
  for (int i = 0; i < count; i++)
    if (!passes[i] || !*passes[i]) return -1;
  if (read_all(in_path, &plain, &plain_len) != 0) return -1;
  name = base_name(in_path);
  name_len = strlen(name);
  if (name_len > 255) goto out;
  payload_len = 2 + name_len + plain_len;
  payload = (uint8_t *)malloc(payload_len);
  cap = 512 + (size_t)count * 160;
  header = (char *)malloc(cap);
  if (!payload || !header) goto out;
  payload[0] = (uint8_t)(name_len >> 8);
  payload[1] = (uint8_t)name_len;
  memcpy(payload + 2, name, name_len);
  memcpy(payload + 2 + name_len, plain, plain_len);
  if (eyas_random(nonce, sizeof(nonce)) != 0 || eyas_random(data_key, sizeof(data_key)) != 0) goto out;
  derive_data_keys(data_key, enc_key, mac_key);
  eyas_chacha20_xor(payload, payload_len, enc_key, nonce);
  eyas_hex_encode(nonce, sizeof(nonce), nonce_hex);
  header_len = (size_t)snprintf(header, cap,
                                EYAS_VAULT_MAGIC "\n"
                                                 "version=5\n"
                                                 "cipher=chacha20\n"
                                                 "mac=hmac-sha256\n"
                                                 "kdf=pbkdf2-sha256\n"
                                                 "policy=multi-recipient\n"
                                                 "iter=%u\n"
                                                 "nonce=%s\n"
                                                 "size=%zu\n"
                                                 "recipients=%d\n",
                                iters, nonce_hex, payload_len, count);
  for (int i = 0; i < count; i++) {
    uint8_t salt[EYAS_SALT_LEN], wrap_nonce[EYAS_NONCE_LEN], wrapped[32];
    char salt_hex[33], wrap_nonce_hex[25], wrapped_hex[65];
    if (eyas_random(salt, sizeof(salt)) != 0 || eyas_random(wrap_nonce, sizeof(wrap_nonce)) != 0) goto out;
    wrap_key(passes[i], salt, iters, zero, wrap_nonce, data_key, wrapped);
    eyas_hex_encode(salt, sizeof(salt), salt_hex);
    eyas_hex_encode(wrap_nonce, sizeof(wrap_nonce), wrap_nonce_hex);
    eyas_hex_encode(wrapped, sizeof(wrapped), wrapped_hex);
    header_len += (size_t)snprintf(header + header_len, cap - header_len, "slot=%s:%s:%s\n", salt_hex, wrap_nonce_hex, wrapped_hex);
    if (header_len >= cap) goto out;
  }
  mac_input = (uint8_t *)malloc(header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, header, header_len);
  memcpy(mac_input + header_len, payload, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, header_len + payload_len, mac);
  eyas_hex_encode(mac, sizeof(mac), mac_hex);
  tag_len = strlen("tag=\n\n") + strlen(mac_hex);
  total_len = header_len + tag_len + payload_len;
  vault = (uint8_t *)malloc(total_len);
  if (!vault) goto out;
  memcpy(vault, header, header_len);
  snprintf((char *)vault + header_len, tag_len + 1, "tag=%s\n\n", mac_hex);
  memcpy(vault + header_len + tag_len, payload, payload_len);
  ok = write_all(out_path, vault, total_len);
out:
  free(plain);
  free(payload);
  free(mac_input);
  free(vault);
  free(header);
  return ok;
}

int eyas_vault_open_multi_file(const char *in_path, const char *out_path, const char *pass) {
  FILE *f = NULL;
  vault_header h;
  const uint8_t zero[32] = {0};
  uint8_t nonce[EYAS_NONCE_LEN], got[EYAS_MAC_LEN], want[EYAS_MAC_LEN], enc_key[32], mac_key[32], data_key[32];
  uint8_t *vault = NULL, *cipher = NULL, *mac_input = NULL, *plain = NULL;
  size_t vault_len = 0, payload_len, nonce_n = 0, tag_n = 0, name_len, plain_len;
  const char *slot;
  int ok = -1, opened = 0;

  if (!pass || !*pass) return -1;
  if (read_all(in_path, &vault, &vault_len) != 0) return -1;
  f = tmpfile();
  if (!f) goto out;
  if (vault_len > 0 && fwrite(vault, 1, vault_len, f) != vault_len) goto out;
  rewind(f);
  if (parse_header(f, &h) != 0 || h.version != 5) goto out;
  payload_len = (size_t)strtoull(h.size, NULL, 10);
  if (payload_len < 2) goto out;
  cipher = (uint8_t *)malloc(payload_len);
  mac_input = (uint8_t *)malloc(h.header_len + payload_len);
  if (!cipher || !mac_input) goto out;
  if (fread(cipher, 1, payload_len, f) != payload_len) goto out;
  if (eyas_hex_decode(h.nonce, nonce, sizeof(nonce), &nonce_n) != 0 || nonce_n != EYAS_NONCE_LEN) goto out;
  if (eyas_hex_decode(h.tag, got, sizeof(got), &tag_n) != 0 || tag_n != EYAS_MAC_LEN) goto out;
  memcpy(mac_input, h.header, h.header_len);
  memcpy(mac_input + h.header_len, cipher, payload_len);
  /* Try the passphrase against every recipient slot until the MAC verifies. */
  for (slot = strstr(h.header, "slot="); slot; slot = strstr(slot + 1, "slot=")) {
    uint8_t salt[EYAS_SALT_LEN], wrap_nonce[EYAS_NONCE_LEN], wrapped[32];
    char salt_hex[33], wrap_nonce_hex[25], wrapped_hex[65];
    size_t sn = 0, wn = 0, kn = 0;
    if (sscanf(slot, "slot=%32[0-9a-f]:%24[0-9a-f]:%64[0-9a-f]", salt_hex, wrap_nonce_hex, wrapped_hex) != 3) continue;
    if (eyas_hex_decode(salt_hex, salt, sizeof(salt), &sn) != 0 || sn != EYAS_SALT_LEN) continue;
    if (eyas_hex_decode(wrap_nonce_hex, wrap_nonce, sizeof(wrap_nonce), &wn) != 0 || wn != EYAS_NONCE_LEN) continue;
    if (eyas_hex_decode(wrapped_hex, wrapped, sizeof(wrapped), &kn) != 0 || kn != 32) continue;
    unwrap_key(pass, salt, h.iter, zero, wrap_nonce, wrapped, data_key);
    derive_data_keys(data_key, enc_key, mac_key);
    eyas_hmac_sha256(mac_key, 32, mac_input, h.header_len + payload_len, want);
    if (eyas_ct_eq(got, want, EYAS_MAC_LEN)) {
      opened = 1;
      break;
    }
  }
  if (!opened) goto out;
  eyas_chacha20_xor(cipher, payload_len, enc_key, nonce);
  name_len = ((size_t)cipher[0] << 8) | cipher[1];
  if (name_len + 2 > payload_len) goto out;
  plain_len = payload_len - 2 - name_len;
  plain = (uint8_t *)malloc(plain_len ? plain_len : 1);
  if (!plain) goto out;
  memcpy(plain, cipher + 2 + name_len, plain_len);
  ok = write_all(out_path, plain, plain_len);
out:
  if (f) fclose(f);
  free(vault);
  free(cipher);
  free(mac_input);
  free(plain);
  return ok;
}

/* Argon2id vault (v6): same layout as the basic vault, but keys come from a
   memory-hard KDF instead of PBKDF2 - far costlier to brute-force on GPU/ASIC. */
int eyas_vault_seal_argon2_file(const char *in_path, const char *out_path, const char *pass, uint32_t a_m, uint32_t a_t, uint32_t a_p) {
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], material[64], mac[EYAS_MAC_LEN];
  char salt_hex[33], nonce_hex[25], mac_hex[65];
  uint8_t *plain = NULL, *payload = NULL, *mac_input = NULL, *vault = NULL;
  size_t plain_len = 0, name_len, payload_len, header_len, tag_len, total_len;
  char header[600];
  const char *name;
  int ok = -1;

  if (!pass || !*pass || a_t < 1 || a_p < 1 || a_m < 8 * a_p) return -1;
  if (read_all(in_path, &plain, &plain_len) != 0) return -1;
  name = base_name(in_path);
  name_len = strlen(name);
  if (name_len > 255) goto out;
  payload_len = 2 + name_len + plain_len;
  payload = (uint8_t *)malloc(payload_len);
  if (!payload) goto out;
  payload[0] = (uint8_t)(name_len >> 8);
  payload[1] = (uint8_t)name_len;
  memcpy(payload + 2, name, name_len);
  memcpy(payload + 2 + name_len, plain, plain_len);
  if (eyas_random(salt, sizeof(salt)) != 0 || eyas_random(nonce, sizeof(nonce)) != 0) goto out;
  if (eyas_argon2id((const uint8_t *)pass, strlen(pass), salt, sizeof(salt), NULL, 0, NULL, 0, a_t, a_m, a_p, material, sizeof(material)) != 0) goto out;
  eyas_chacha20_xor(payload, payload_len, material, nonce);
  eyas_hex_encode(salt, sizeof(salt), salt_hex);
  eyas_hex_encode(nonce, sizeof(nonce), nonce_hex);
  header_len = (size_t)snprintf(header, sizeof(header),
                                EYAS_VAULT_MAGIC "\n"
                                                 "version=6\n"
                                                 "cipher=chacha20\n"
                                                 "mac=hmac-sha256\n"
                                                 "kdf=argon2id\n"
                                                 "argon2_m=%u\n"
                                                 "argon2_t=%u\n"
                                                 "argon2_p=%u\n"
                                                 "salt=%s\n"
                                                 "nonce=%s\n"
                                                 "size=%zu\n",
                                a_m, a_t, a_p, salt_hex, nonce_hex, payload_len);
  if (header_len >= sizeof(header)) goto out;
  mac_input = (uint8_t *)malloc(header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, header, header_len);
  memcpy(mac_input + header_len, payload, payload_len);
  eyas_hmac_sha256(material + 32, 32, mac_input, header_len + payload_len, mac);
  eyas_hex_encode(mac, sizeof(mac), mac_hex);
  tag_len = strlen("tag=\n\n") + strlen(mac_hex);
  total_len = header_len + tag_len + payload_len;
  vault = (uint8_t *)malloc(total_len);
  if (!vault) goto out;
  memcpy(vault, header, header_len);
  snprintf((char *)vault + header_len, tag_len + 1, "tag=%s\n\n", mac_hex);
  memcpy(vault + header_len + tag_len, payload, payload_len);
  ok = write_all(out_path, vault, total_len);
out:
  free(plain);
  free(payload);
  free(mac_input);
  free(vault);
  return ok;
}

int eyas_vault_open_argon2_file(const char *in_path, const char *out_path, const char *pass) {
  FILE *f = NULL;
  vault_header h;
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], got[EYAS_MAC_LEN], want[EYAS_MAC_LEN], material[64];
  uint8_t *vault = NULL, *cipher = NULL, *mac_input = NULL, *plain = NULL;
  size_t vault_len = 0, payload_len, salt_n = 0, nonce_n = 0, tag_n = 0, name_len, plain_len;
  int ok = -1;

  if (!pass || !*pass) return -1;
  if (read_all(in_path, &vault, &vault_len) != 0) return -1;
  f = tmpfile();
  if (!f) goto out;
  if (vault_len > 0 && fwrite(vault, 1, vault_len, f) != vault_len) goto out;
  rewind(f);
  if (parse_header(f, &h) != 0 || h.version != 6 || strcmp(h.kdf, "argon2id") != 0) goto out;
  payload_len = (size_t)strtoull(h.size, NULL, 10);
  if (payload_len < 2) goto out;
  cipher = (uint8_t *)malloc(payload_len);
  if (!cipher) goto out;
  if (fread(cipher, 1, payload_len, f) != payload_len) goto out;
  if (eyas_hex_decode(h.salt, salt, sizeof(salt), &salt_n) != 0 || salt_n != EYAS_SALT_LEN) goto out;
  if (eyas_hex_decode(h.nonce, nonce, sizeof(nonce), &nonce_n) != 0 || nonce_n != EYAS_NONCE_LEN) goto out;
  if (eyas_hex_decode(h.tag, got, sizeof(got), &tag_n) != 0 || tag_n != EYAS_MAC_LEN) goto out;
  if (eyas_argon2id((const uint8_t *)pass, strlen(pass), salt, sizeof(salt), NULL, 0, NULL, 0, h.a_t, h.a_m, h.a_p, material, sizeof(material)) != 0) goto out;
  mac_input = (uint8_t *)malloc(h.header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, h.header, h.header_len);
  memcpy(mac_input + h.header_len, cipher, payload_len);
  eyas_hmac_sha256(material + 32, 32, mac_input, h.header_len + payload_len, want);
  if (!eyas_ct_eq(got, want, EYAS_MAC_LEN)) goto out;
  eyas_chacha20_xor(cipher, payload_len, material, nonce);
  name_len = ((size_t)cipher[0] << 8) | cipher[1];
  if (name_len + 2 > payload_len) goto out;
  plain_len = payload_len - 2 - name_len;
  plain = (uint8_t *)malloc(plain_len ? plain_len : 1);
  if (!plain) goto out;
  memcpy(plain, cipher + 2 + name_len, plain_len);
  ok = write_all(out_path, plain, plain_len);
out:
  if (f) fclose(f);
  free(vault);
  free(cipher);
  free(mac_input);
  free(plain);
  return ok;
}

/* - Deniable hidden vaults (v7) -
   A container holds two equal-size slots after a small public header. Each slot
   is salt(16)|nonce(12)|ChaCha20(body). The body decrypts to a magic, an inner
   HMAC and the payload, then random padding; without the right passphrase a slot
   is indistinguishable from random bytes. The decoy lives in slot 0; the hidden
   payload (if any) lives in slot 1, otherwise slot 1 is pure random. The holder
   of the decoy passphrase therefore cannot prove a hidden volume exists. */
#define EYAS_DEN_HDR 28 /* salt(16) + nonce(12) */
#define EYAS_DEN_MAGIC "EYASHID1"
#define EYAS_DEN_OVERHEAD (EYAS_DEN_HDR + 8 + 2 + 4 + EYAS_MAC_LEN)

static int den_build_slot(const char *pass, const uint8_t *data, uint32_t data_len, const char *name, uint32_t slot_size, uint32_t iters, uint8_t *slot) {
  uint8_t enc[32], mac[32], hmac[32];
  uint8_t *body = slot + EYAS_DEN_HDR;
  uint32_t body_len = slot_size - EYAS_DEN_HDR;
  size_t name_len = strlen(name), used;
  if (name_len > 255) return -1;
  used = 8 + 2 + 4 + name_len + data_len;
  if (used + EYAS_MAC_LEN > body_len) return -1;
  if (eyas_random(slot, 16) != 0 || eyas_random(slot + 16, 12) != 0) return -1;
  if (eyas_random(body, body_len) != 0) return -1; /* random padding everywhere first */
  memcpy(body, EYAS_DEN_MAGIC, 8);
  body[8] = (uint8_t)(name_len >> 8);
  body[9] = (uint8_t)name_len;
  body[10] = (uint8_t)(data_len >> 24);
  body[11] = (uint8_t)(data_len >> 16);
  body[12] = (uint8_t)(data_len >> 8);
  body[13] = (uint8_t)data_len;
  memcpy(body + 14, name, name_len);
  memcpy(body + 14 + name_len, data, data_len);
  derive(pass, slot, iters, enc, mac);
  eyas_hmac_sha256(mac, 32, body, used, hmac);
  memcpy(body + used, hmac, EYAS_MAC_LEN);
  eyas_chacha20_xor(body, body_len, enc, slot + 16);
  return 0;
}

static int den_open_slot(const char *pass, const uint8_t *slot, uint32_t slot_size, uint32_t iters, uint8_t **out, uint32_t *out_len) {
  uint8_t enc[32], mac[32], want[32], *body;
  uint32_t body_len = slot_size - EYAS_DEN_HDR, name_len, data_len, used;
  int ok = -1;
  body = (uint8_t *)malloc(body_len);
  if (!body) return -1;
  memcpy(body, slot + EYAS_DEN_HDR, body_len);
  derive(pass, slot, iters, enc, mac);
  eyas_chacha20_xor(body, body_len, enc, slot + 16);
  if (memcmp(body, EYAS_DEN_MAGIC, 8) != 0) goto out;
  name_len = ((uint32_t)body[8] << 8) | body[9];
  data_len = ((uint32_t)body[10] << 24) | ((uint32_t)body[11] << 16) | ((uint32_t)body[12] << 8) | body[13];
  used = 8 + 2 + 4 + name_len + data_len;
  if (used + EYAS_MAC_LEN > body_len) goto out;
  eyas_hmac_sha256(mac, 32, body, used, want);
  if (!eyas_ct_eq(body + used, want, EYAS_MAC_LEN)) goto out;
  *out = (uint8_t *)malloc(data_len ? data_len : 1);
  if (!*out) goto out;
  memcpy(*out, body + 14 + name_len, data_len);
  *out_len = data_len;
  ok = 0;
out:
  free(body);
  return ok;
}

int eyas_vault_seal_deniable_file(const char *decoy_path, const char *out_path, const char *decoy_pass, const char *hidden_path, const char *hidden_pass, uint32_t iters) {
  uint8_t *decoy = NULL, *hidden = NULL, *vault = NULL;
  size_t decoy_len = 0, hidden_len = 0, header_len, total;
  uint32_t slot_size, need;
  char header[256];
  int ok = -1;

  if (!decoy_pass || !*decoy_pass || iters < 10000U) return -1;
  if (read_all(decoy_path, &decoy, &decoy_len) != 0) return -1;
  if (hidden_path) {
    if (!hidden_pass || !*hidden_pass) goto out;
    if (read_all(hidden_path, &hidden, &hidden_len) != 0) goto out;
  }
  need = (uint32_t)(decoy_len > hidden_len ? decoy_len : hidden_len) + 256 + EYAS_DEN_OVERHEAD;
  slot_size = ((need + 4095) / 4096) * 4096; /* round up; size only reveals capacity */
  header_len = (size_t)snprintf(header, sizeof(header),
                                EYAS_VAULT_MAGIC "\n"
                                                 "version=7\n"
                                                 "cipher=chacha20\n"
                                                 "mac=hmac-sha256\n"
                                                 "kdf=pbkdf2-sha256\n"
                                                 "policy=deniable\n"
                                                 "iter=%u\n"
                                                 "slots=2\n"
                                                 "slot_size=%u\n\n",
                                iters, slot_size);
  total = header_len + 2 * (size_t)slot_size;
  vault = (uint8_t *)malloc(total);
  if (!vault) goto out;
  memcpy(vault, header, header_len);
  if (den_build_slot(decoy_pass, decoy, (uint32_t)decoy_len, base_name(decoy_path), slot_size, iters, vault + header_len) != 0) goto out;
  if (hidden_path) {
    if (den_build_slot(hidden_pass, hidden, (uint32_t)hidden_len, base_name(hidden_path), slot_size, iters, vault + header_len + slot_size) != 0) goto out;
  } else {
    if (eyas_random(vault + header_len + slot_size, slot_size) != 0) goto out; /* indistinguishable random */
  }
  ok = write_all(out_path, vault, total);
out:
  free(decoy);
  free(hidden);
  free(vault);
  return ok;
}

int eyas_vault_open_deniable_file(const char *in_path, const char *out_path, const char *pass) {
  uint8_t *vault = NULL, *out = NULL;
  size_t vault_len = 0;
  uint32_t slot_size = 0, iters = 0, out_len = 0;
  size_t header_len = 0;
  const char *body;
  int ok = -1;

  if (!pass || !*pass) return -1;
  if (read_all(in_path, &vault, &vault_len) != 0) return -1;
  body = strstr((char *)vault, "\n\n");
  if (!body) goto out;
  header_len = (size_t)(body - (char *)vault) + 2;
  {
    const char *p = strstr((char *)vault, "iter=");
    if (p) iters = (uint32_t)strtoul(p + 5, NULL, 10);
  }
  {
    const char *p = strstr((char *)vault, "slot_size=");
    if (p) slot_size = (uint32_t)strtoul(p + 10, NULL, 10);
  }
  if (!iters || slot_size < EYAS_DEN_OVERHEAD || header_len + 2 * (size_t)slot_size > vault_len) goto out;
  /* Try slot 0 (decoy) then slot 1 (hidden). */
  if (den_open_slot(pass, vault + header_len, slot_size, iters, &out, &out_len) == 0 ||
      den_open_slot(pass, vault + header_len + slot_size, slot_size, iters, &out, &out_len) == 0) {
    ok = write_all(out_path, out, out_len);
  }
out:
  free(vault);
  free(out);
  return ok;
}

int eyas_vault_seal_file(const char *in_path, const char *out_path, const char *pass, uint32_t iters) {
  uint8_t *plain = NULL, *vault = NULL;
  size_t plain_len = 0, vault_len = 0;
  int ok = -1;
  if (read_all(in_path, &plain, &plain_len) != 0) return -1;
  if (eyas_vault_seal_memory(plain, plain_len, base_name(in_path), pass, iters, &vault, &vault_len) != 0) goto out;
  ok = write_all(out_path, vault, vault_len);
out:
  free(plain);
  free(vault);
  return ok;
}

int eyas_vault_seal_file_device(const char *in_path, const char *out_path, const char *pass, uint32_t iters, const char *device_path) {
  uint8_t *plain = NULL, *vault = NULL, device_secret[32];
  size_t plain_len = 0, vault_len = 0;
  char device_id[EYAS_HASH_HEX];
  int ok = -1;
  if (read_device_secret(device_path, device_secret, device_id) != 0) return -1;
  if (read_all(in_path, &plain, &plain_len) != 0) return -1;
  if (vault_seal_memory_device(plain, plain_len, base_name(in_path), pass, iters, device_secret, device_id, &vault, &vault_len) != 0) goto out;
  ok = write_all(out_path, vault, vault_len);
out:
  free(plain);
  free(vault);
  return ok;
}

int eyas_vault_open_file(const char *in_path, const char *out_path, const char *pass) {
  uint8_t *vault = NULL, *plain = NULL;
  size_t vault_len = 0, plain_len = 0;
  char name[256];
  int ok = -1;
  if (read_all(in_path, &vault, &vault_len) != 0) return -1;
  if (eyas_vault_open_memory(vault, vault_len, pass, &plain, &plain_len, name, sizeof(name)) != 0) goto out;
  ok = write_all(out_path, plain, plain_len);
out:
  free(vault);
  free(plain);
  return ok;
}

int eyas_vault_open_file_device(const char *in_path, const char *out_path, const char *pass, const char *device_path) {
  uint8_t *vault = NULL, *plain = NULL;
  size_t vault_len = 0, plain_len = 0;
  char name[256];
  int ok = -1;
  if (read_all(in_path, &vault, &vault_len) != 0) return -1;
  g_open_device_path = device_path;
  if (eyas_vault_open_memory(vault, vault_len, pass, &plain, &plain_len, name, sizeof(name)) != 0) goto out;
  ok = write_all(out_path, plain, plain_len);
out:
  g_open_device_path = NULL;
  free(vault);
  free(plain);
  return ok;
}

int eyas_vault_open_memory(const uint8_t *vault, size_t vault_len, const char *pass, uint8_t **out_buf, size_t *out_len, char *name, size_t name_cap) {
  FILE *f = NULL;
  vault_header h;
  uint8_t salt[EYAS_SALT_LEN], nonce[EYAS_NONCE_LEN], got[EYAS_MAC_LEN], want[EYAS_MAC_LEN], enc_key[32], mac_key[32];
  uint8_t *cipher = NULL, *mac_input = NULL;
  size_t n = 0, payload_len, salt_n = 0, nonce_n = 0, tag_n = 0, name_len;
  int ok = -1;

  if (!pass || !*pass) return -1;
  f = tmpfile();
  if (!f) return -1;
  if (vault_len > 0 && fwrite(vault, 1, vault_len, f) != vault_len) goto out;
  rewind(f);
  if (parse_header(f, &h) != 0) goto out;
  payload_len = (size_t)strtoull(h.size, NULL, 10);
  if (payload_len < 2) goto out;
  cipher = (uint8_t *)malloc(payload_len);
  if (!cipher) goto out;
  n = fread(cipher, 1, payload_len, f);
  if (n != payload_len) goto out;
  if (eyas_hex_decode(h.salt, salt, sizeof(salt), &salt_n) != 0 || salt_n != EYAS_SALT_LEN) goto out;
  if (eyas_hex_decode(h.nonce, nonce, sizeof(nonce), &nonce_n) != 0 || nonce_n != EYAS_NONCE_LEN) goto out;
  if (eyas_hex_decode(h.tag, got, sizeof(got), &tag_n) != 0 || tag_n != EYAS_MAC_LEN) goto out;
  if (h.version == 1) {
    derive(pass, salt, h.iter, enc_key, mac_key);
  } else if (h.version == 2) {
    uint8_t device_secret[32], wrap_nonce[EYAS_NONCE_LEN], wrapped[32], data_key[32];
    size_t wrap_nonce_n = 0, wrapped_n = 0;
    char got_device_id[EYAS_HASH_HEX];
    if (!g_open_device_path) goto out;
    if (read_device_secret(g_open_device_path, device_secret, got_device_id) != 0) goto out;
    if (strcmp(got_device_id, h.device_id) != 0) goto out;
    if (eyas_hex_decode(h.wrap_nonce, wrap_nonce, sizeof(wrap_nonce), &wrap_nonce_n) != 0 || wrap_nonce_n != EYAS_NONCE_LEN) goto out;
    if (eyas_hex_decode(h.wrapped_key, wrapped, sizeof(wrapped), &wrapped_n) != 0 || wrapped_n != 32) goto out;
    unwrap_key(pass, salt, h.iter, device_secret, wrap_nonce, wrapped, data_key);
    derive_data_keys(data_key, enc_key, mac_key);
  } else {
    goto out;
  }
  mac_input = (uint8_t *)malloc(h.header_len + payload_len);
  if (!mac_input) goto out;
  memcpy(mac_input, h.header, h.header_len);
  memcpy(mac_input + h.header_len, cipher, payload_len);
  eyas_hmac_sha256(mac_key, 32, mac_input, h.header_len + payload_len, want);
  if (!eyas_ct_eq(got, want, EYAS_MAC_LEN)) goto out;
  eyas_chacha20_xor(cipher, payload_len, enc_key, nonce);
  name_len = ((size_t)cipher[0] << 8) | cipher[1];
  if (name_len + 2 > payload_len) goto out;
  if (name && name_cap > 0) {
    size_t c = name_len + 1 > name_cap ? name_cap - 1 : name_len;
    memcpy(name, cipher + 2, c);
    name[c] = '\0';
  }
  *out_len = payload_len - 2 - name_len;
  *out_buf = (uint8_t *)malloc(*out_len);
  if (*out_len > 0 && !*out_buf) goto out;
  memcpy(*out_buf, cipher + 2 + name_len, *out_len);
  ok = 0;
out:
  if (f) fclose(f);
  free(cipher);
  free(mac_input);
  return ok;
}

int eyas_vault_version_of(const char *path) {
  FILE *f = fopen(path, "rb");
  char line[256];
  int v = -1;
  if (!f) return -1;
  /* Read only the version= line; the deniable (v7) layout has no tag/nonce and
     would not pass full header validation. */
  if (read_line(f, line, sizeof(line)) == 0 && strcmp(line, EYAS_VAULT_MAGIC) == 0) {
    while (read_line(f, line, sizeof(line)) == 0) {
      if (line[0] == '\0') break;
      if (strncmp(line, "version=", 8) == 0) {
        v = atoi(line + 8);
        break;
      }
    }
  }
  fclose(f);
  return v;
}

int eyas_vault_info(const char *path) {
  FILE *f = fopen(path, "rb");
  vault_header h;
  if (!f) return -1;
  if (eyas_vault_version_of(path) == 7) { /* deniable: print only the public header */
    char line[256];
    while (read_line(f, line, sizeof(line)) == 0 && line[0]) printf("%s\n", line);
    fclose(f);
    return 0;
  }
  if (parse_header(f, &h) != 0) {
    fclose(f);
    return -1;
  }
  fclose(f);
  printf("format=%s\nversion=%d\ncipher=chacha20\nmac=hmac-sha256\nsize=%s\n",
         EYAS_VAULT_MAGIC, h.version, h.size);
  if (h.version != 6) printf("kdf=pbkdf2-sha256\niter=%u\n", h.iter);
  if (h.salt[0]) printf("salt=%s\n", h.salt);
  printf("nonce=%s\n", h.nonce);
  if (h.version == 2) {
    printf("policy=passphrase+device-key\ndevice_id=%s\nwrap_nonce=%s\nwrapped_key=%s\n", h.device_id, h.wrap_nonce, h.wrapped_key);
  }
  if (h.version == 3) {
    printf("policy=passphrase+threshold\ngroup_id=%s\nthreshold=%d\nshares=%d\nwrap_nonce=%s\nwrapped_key=%s\n", h.group_id, h.threshold, h.shares, h.wrap_nonce, h.wrapped_key);
  }
  if (h.version == 4) {
    printf("policy=passphrase+timelock\ntimelock_seed=%s\ntimelock_steps=%llu\nwrap_nonce=%s\nwrapped_key=%s\n", h.timelock_seed, h.timelock_steps, h.wrap_nonce, h.wrapped_key);
  }
  if (h.version == 5) {
    printf("policy=multi-recipient\nrecipients=%d\n", h.recipients);
  }
  if (h.version == 6) {
    printf("policy=passphrase\nkdf=argon2id\nargon2_m=%u\nargon2_t=%u\nargon2_p=%u\n", h.a_m, h.a_t, h.a_p);
  }
  printf("tag=%s\n", h.tag);
  return 0;
}
