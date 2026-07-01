/*
 * eyas_crypt.h
 * author: @cocomelonc
 * https://cocomelonc.github.io
*/
#ifndef EYAS_CRYPT_H
#define EYAS_CRYPT_H

#include <stddef.h>
#include <stdint.h>

#define EYAS_CRYPT_VERSION "0.1.0"
#define EYAS_VAULT_MAGIC "EYASCRYPT1"
#define EYAS_HASH_HEX 65
#define EYAS_MAX_PATH 4096
#define EYAS_SALT_LEN 16
#define EYAS_NONCE_LEN 12
#define EYAS_MAC_LEN 32
#define EYAS_KEY_LEN 32
#define EYAS_DEFAULT_ITERS 200000U

void eyas_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void eyas_sha256_hex(const uint8_t *data, size_t len, char out[EYAS_HASH_HEX]);

void eyas_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);
void eyas_pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t salt_len, uint32_t iters, uint8_t *out, size_t out_len);
void eyas_chacha20_xor(uint8_t *buf, size_t len, const uint8_t key[32], const uint8_t nonce[12]);
int eyas_random(uint8_t *buf, size_t len);
void eyas_hex_encode(const uint8_t *in, size_t len, char *out);
int eyas_hex_decode(const char *in, uint8_t *out, size_t out_len, size_t *written);
int eyas_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);

int eyas_vault_seal_file(const char *in_path, const char *out_path, const char *pass, uint32_t iters);
int eyas_vault_open_file(const char *in_path, const char *out_path, const char *pass);
int eyas_vault_seal_file_device(const char *in_path, const char *out_path, const char *pass, uint32_t iters, const char *device_path);
int eyas_vault_open_file_device(const char *in_path, const char *out_path, const char *pass, const char *device_path);
int eyas_vault_info(const char *path);
int eyas_vault_version_of(const char *path);
int eyas_vault_seal_memory(const uint8_t *plain, size_t plain_len, const char *name, const char *pass, uint32_t iters, uint8_t **out, size_t *out_len);
int eyas_vault_open_memory(const uint8_t *vault, size_t vault_len, const char *pass, uint8_t **out, size_t *out_len, char *name, size_t name_len);
int eyas_device_enroll(const char *path);
int eyas_device_id(const char *path, char out[EYAS_HASH_HEX]);

/* Argon2id (RFC 9106) memory-hard KDF. m is in KiB, t passes, p lanes. */
int eyas_argon2id(const uint8_t *pwd, size_t pwdlen, const uint8_t *salt, size_t saltlen, const uint8_t *secret, size_t secretlen, const uint8_t *ad, size_t adlen, uint32_t t, uint32_t m, uint32_t p, uint8_t *out, size_t outlen);

/* Shamir Secret Sharing over GF(2^8). A share is 33 bytes: [x, y0..y31]. */
int eyas_shamir_split(const uint8_t secret[32], int k, int n, uint8_t *shares);
int eyas_shamir_combine(const uint8_t *shares, int count, uint8_t secret[32]);

/* Threshold "split-key" vaults: passphrase + K-of-N Shamir shares. */
int eyas_vault_seal_threshold_memory(const uint8_t *plain, size_t plain_len, const char *name, const char *pass, uint32_t iters, int k, int n, uint8_t **out, size_t *out_len, uint8_t *shares, char group_id[EYAS_HASH_HEX]);
int eyas_vault_open_threshold_memory(const uint8_t *vault, size_t vault_len, const char *pass, const uint8_t *shares, int count, uint8_t **out, size_t *out_len, char *name, size_t name_len);
int eyas_vault_seal_threshold_file(const char *in_path, const char *out_path, const char *pass, uint32_t iters, int k, int n);
int eyas_vault_open_threshold_file(const char *in_path, const char *out_path, const char *pass, const char **share_paths, int count);

/* Time-lock vaults: opening requires a sequential, non-parallelizable delay. */
int eyas_vault_seal_timelock_file(const char *in_path, const char *out_path, const char *pass, uint32_t iters, double seconds);
int eyas_vault_open_timelock_file(const char *in_path, const char *out_path, const char *pass);

/* Multi-recipient vaults: any one of N passphrases opens the same vault. */
int eyas_vault_seal_multi_file(const char *in_path, const char *out_path, const char **passes, int count, uint32_t iters);
int eyas_vault_open_multi_file(const char *in_path, const char *out_path, const char *pass);

/* Argon2id-KDF vault: memory-hard key stretching instead of PBKDF2. */
int eyas_vault_seal_argon2_file(const char *in_path, const char *out_path, const char *pass, uint32_t a_m, uint32_t a_t, uint32_t a_p);
int eyas_vault_open_argon2_file(const char *in_path, const char *out_path, const char *pass);

/* Deniable hidden vaults: a decoy and an optional hidden payload share one
   container; the decoy passphrase cannot prove the hidden payload exists. */
int eyas_vault_seal_deniable_file(const char *decoy_path, const char *out_path, const char *decoy_pass, const char *hidden_path, const char *hidden_pass, uint32_t iters);
int eyas_vault_open_deniable_file(const char *in_path, const char *out_path, const char *pass);

int eyas_gui_run(const char *bind_ip, int port);

#endif
