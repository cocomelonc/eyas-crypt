/*
 * main.c
 * author: @cocomelonc
 * https://cocomelonc.github.io
*/
#include "eyas_crypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *arg_value(int argc, char **argv, const char *name, const char *def) {
  for (int i = 0; i + 1 < argc; i++) {
    if (strcmp(argv[i], name) == 0) return argv[i + 1];
  }
  return def;
}

static int has_flag(int argc, char **argv, const char *name) {
  for (int i = 0; i < argc; i++)
    if (strcmp(argv[i], name) == 0) return 1;
  return 0;
}

static int collect_values(int argc, char **argv, const char *name, const char **out, int max) {
  int count = 0;
  for (int i = 0; i + 1 < argc && count < max; i++) {
    if (strcmp(argv[i], name) == 0) out[count++] = argv[i + 1];
  }
  return count;
}

static void usage(void) {
  puts("eyas-crypt " EYAS_CRYPT_VERSION);
  puts("usage:");
  puts("  eyas-crypt enroll-device <device.key>");
  puts("  eyas-crypt device-id <device.key>");
  puts("  eyas-crypt seal <input> <vault.eyas> --pass passphrase [--device device.key] [--iter 200000]");
  puts("  eyas-crypt seal <input> <vault.eyas> --pass passphrase --threshold K --shares N");
  puts("  eyas-crypt seal <input> <vault.eyas> --pass passphrase --timelock SECONDS");
  puts("  eyas-crypt seal <input> <vault.eyas> --recipient passA --recipient passB ...");
  puts("  eyas-crypt seal <input> <vault.eyas> --pass passphrase --kdf argon2id [--argon-m 65536]");
  puts("  eyas-crypt seal <decoy> <vault.eyas> --pass decoyPass --hidden <secret> --hidden-pass hiddenPass");
  puts("  eyas-crypt open <vault.eyas> <output> --pass passphrase [--device device.key]");
  puts("  eyas-crypt open <vault.eyas> <output> --pass passphrase --share s1.share --share s2.share ...");
  puts("  eyas-crypt info <vault.eyas>");
  puts("  eyas-crypt gui [--bind 127.0.0.1] [--port 8765]");
}

int main(int argc, char **argv) {
  const char *pass = arg_value(argc, argv, "--pass", getenv("EYAS_PASS"));
  if (argc < 2) {
    usage();
    return 2;
  }
  if (strcmp(argv[1], "enroll-device") == 0) {
    if (argc < 3 || eyas_device_enroll(argv[2]) != 0) {
      fprintf(stderr, "device enrollment failed\n");
      return 1;
    }
    printf("device key written: %s\n", argv[2]);
    return 0;
  }
  if (strcmp(argv[1], "device-id") == 0) {
    char id[EYAS_HASH_HEX];
    if (argc < 3 || eyas_device_id(argv[2], id) != 0) {
      fprintf(stderr, "invalid device key\n");
      return 1;
    }
    puts(id);
    return 0;
  }
  if (strcmp(argv[1], "seal") == 0) {
    uint32_t iters = (uint32_t)strtoul(arg_value(argc, argv, "--iter", "200000"), NULL, 10);
    const char *device = arg_value(argc, argv, "--device", NULL);
    int threshold = atoi(arg_value(argc, argv, "--threshold", "0"));
    int shares = atoi(arg_value(argc, argv, "--shares", "0"));
    double timelock = atof(arg_value(argc, argv, "--timelock", "0"));
    const char *recipients[64];
    int recipient_count = collect_values(argc, argv, "--recipient", recipients, 64);
    const char *kdf = arg_value(argc, argv, "--kdf", "pbkdf2");
    const char *hidden = arg_value(argc, argv, "--hidden", NULL);
    const char *hidden_pass = arg_value(argc, argv, "--hidden-pass", NULL);
    int deniable = has_flag(argc, argv, "--deniable") || hidden;
    int rc;
    if (argc < 4 || (recipient_count == 0 && (!pass || !*pass))) {
      usage();
      return 2;
    }
    if (recipient_count > 0) {
      rc = eyas_vault_seal_multi_file(argv[2], argv[3], recipients, recipient_count, iters);
    } else if (deniable) {
      rc = eyas_vault_seal_deniable_file(argv[2], argv[3], pass, hidden, hidden_pass, iters);
    } else if (strcmp(kdf, "argon2id") == 0) {
      uint32_t a_m = (uint32_t)strtoul(arg_value(argc, argv, "--argon-m", "65536"), NULL, 10);
      uint32_t a_t = (uint32_t)strtoul(arg_value(argc, argv, "--argon-t", "3"), NULL, 10);
      uint32_t a_p = (uint32_t)strtoul(arg_value(argc, argv, "--argon-p", "1"), NULL, 10);
      rc = eyas_vault_seal_argon2_file(argv[2], argv[3], pass, a_m, a_t, a_p);
    } else if (threshold || shares) {
      if (threshold < 2 || shares < threshold || shares > 255) {
        fprintf(stderr, "threshold needs 2 <= K <= N <= 255\n");
        return 2;
      }
      rc = eyas_vault_seal_threshold_file(argv[2], argv[3], pass, iters, threshold, shares);
    } else if (timelock > 0) {
      rc = eyas_vault_seal_timelock_file(argv[2], argv[3], pass, iters, timelock);
    } else if (device) {
      rc = eyas_vault_seal_file_device(argv[2], argv[3], pass, iters, device);
    } else {
      rc = eyas_vault_seal_file(argv[2], argv[3], pass, iters);
    }
    if (rc != 0) {
      fprintf(stderr, "seal failed\n");
      return 1;
    }
    printf("sealed %s -> %s\n", argv[2], argv[3]);
    return 0;
  }
  if (strcmp(argv[1], "open") == 0) {
    const char *device = arg_value(argc, argv, "--device", NULL);
    const char *share_paths[256];
    int share_count = collect_values(argc, argv, "--share", share_paths, 256);
    int rc;
    if (argc < 4 || !pass || !*pass) {
      usage();
      return 2;
    }
    if (share_count > 0) {
      rc = eyas_vault_open_threshold_file(argv[2], argv[3], pass, share_paths, share_count);
    } else if (device) {
      rc = eyas_vault_open_file_device(argv[2], argv[3], pass, device);
    } else if (eyas_vault_version_of(argv[2]) == 4) {
      rc = eyas_vault_open_timelock_file(argv[2], argv[3], pass);
    } else if (eyas_vault_version_of(argv[2]) == 5) {
      rc = eyas_vault_open_multi_file(argv[2], argv[3], pass);
    } else if (eyas_vault_version_of(argv[2]) == 6) {
      rc = eyas_vault_open_argon2_file(argv[2], argv[3], pass);
    } else if (eyas_vault_version_of(argv[2]) == 7) {
      rc = eyas_vault_open_deniable_file(argv[2], argv[3], pass);
    } else {
      rc = eyas_vault_open_file(argv[2], argv[3], pass);
    }
    if (rc != 0) {
      fprintf(stderr, "open failed: bad passphrase, missing/insufficient shares, or tampered vault\n");
      return 1;
    }
    printf("opened %s -> %s\n", argv[2], argv[3]);
    return 0;
  }
  if (strcmp(argv[1], "info") == 0) {
    if (argc < 3 || eyas_vault_info(argv[2]) != 0) {
      fprintf(stderr, "not an eyas vault\n");
      return 1;
    }
    return 0;
  }
  if (strcmp(argv[1], "selftest") == 0) {
    /* Argon2id against the RFC 9106 test vector. */
    uint8_t p32[32], s16[16], sec[8], ad[12], out[32];
    static const uint8_t want[32] = {0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
                                     0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59};
    memset(p32, 1, 32);
    memset(s16, 2, 16);
    memset(sec, 3, 8);
    memset(ad, 4, 12);
    eyas_argon2id(p32, 32, s16, 16, sec, 8, ad, 12, 3, 32, 4, out, 32);
    if (memcmp(out, want, 32) != 0) {
      fprintf(stderr, "argon2id self-test FAILED\n");
      return 1;
    }
    puts("selftest ok: argon2id matches RFC 9106 vector");
    return 0;
  }
  if (strcmp(argv[1], "gui") == 0) {
    const char *bind_ip = arg_value(argc, argv, "--bind", "127.0.0.1");
    int port = atoi(arg_value(argc, argv, "--port", "8765"));
    return eyas_gui_run(bind_ip, port);
  }
  usage();
  return 2;
}
