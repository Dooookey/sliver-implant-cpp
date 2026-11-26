/* tests/unit/test_cipher.c - CipherContext frame must match the Go reference.
 *
 * SLIVER_CIPHER_FIXTURES contains cipher-<name>.bin (Go Encrypt output) and
 * cipher-<name>.raw. The key is fixed (bytes 1..32) on both sides. After
 * verifying Go -> C, this writes ours-cipher-<name>.bin for the Go side to
 * decrypt (tests/gzipfix check).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/crypto.h"

#ifndef SLIVER_CIPHER_FIXTURES
#define SLIVER_CIPHER_FIXTURES "build"
#endif

static int failures = 0;

static unsigned char *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  unsigned char *buf;
  long size;
  if (f == NULL) {
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  size = ftell(f);
  if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  buf = (unsigned char *)malloc((size_t)size + 1);
  if (buf == NULL) {
    fclose(f);
    return NULL;
  }
  if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)size;
  return buf;
}

static int write_file(const char *path, const void *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    return -1;
  }
  if (len != 0 && fwrite(data, 1, len, f) != len) {
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static void roundtrip(const char *dir, const char *name, const unsigned char key[32]) {
  char ct_path[512];
  char raw_path[512];
  char ours_path[512];
  unsigned char *ct;
  unsigned char *raw;
  size_t ct_len = 0;
  size_t raw_len = 0;

  (void)snprintf(ct_path, sizeof(ct_path), "%s/cipher-%s.bin", dir, name);
  (void)snprintf(raw_path, sizeof(raw_path), "%s/cipher-%s.raw", dir, name);
  (void)snprintf(ours_path, sizeof(ours_path), "%s/ours-cipher-%s.bin", dir, name);

  ct = read_file(ct_path, &ct_len);
  raw = read_file(raw_path, &raw_len);
  if (ct == NULL || raw == NULL) {
    printf("SKIP %s (fixtures missing)\n", name);
    free(ct);
    free(raw);
    return;
  }

  {
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    if (sliver_cipher_decrypt(key, ct, ct_len, &plain, &plain_len) != 0) {
      printf("FAIL %s: cannot decrypt Go ciphertext\n", name);
      failures++;
    } else {
      if (plain_len != raw_len || memcmp(plain, raw, raw_len) != 0) {
        printf("FAIL %s: decrypted %u bytes, expected %u\n", name, (unsigned)plain_len,
               (unsigned)raw_len);
        failures++;
      }
      free(plain);
    }
  }

  {
    unsigned char *ours = NULL;
    size_t ours_len = 0;
    unsigned char *back = NULL;
    size_t back_len = 0;
    if (sliver_cipher_encrypt(key, raw, raw_len, &ours, &ours_len) != 0) {
      printf("FAIL %s: cannot encrypt\n", name);
      failures++;
    } else {
      if (sliver_cipher_decrypt(key, ours, ours_len, &back, &back_len) != 0 ||
          back_len != raw_len || memcmp(back, raw, raw_len) != 0) {
        printf("FAIL %s: C round-trip mismatch\n", name);
        failures++;
      }
      free(back);
      if (write_file(ours_path, ours, ours_len) != 0) {
        printf("FAIL %s: cannot write %s\n", name, ours_path);
        failures++;
      }
      free(ours);
    }
  }

  free(ct);
  free(raw);
}

int main(void) {
  static const char *names[] = {"c1", "c2", "c3"};
  unsigned char key[32];
  size_t i;

  for (i = 0; i < sizeof(key); ++i) {
    key[i] = (unsigned char)(i + 1);
  }
  for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    roundtrip(SLIVER_CIPHER_FIXTURES, names[i], key);
  }
  if (failures != 0) {
    printf("test_cipher: %d failure(s)\n", failures);
    return 1;
  }
  printf("test_cipher: PASS\n");
  return 0;
}
