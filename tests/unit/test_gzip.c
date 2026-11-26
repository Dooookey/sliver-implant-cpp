/* tests/unit/test_gzip.c - gzip must round-trip with the Go reference.
 *
 * SLIVER_GZIP_FIXTURES points at a directory containing fixture-<name>.gz
 * (produced by Go's compress/gzip at BestSpeed) and fixture-<name>.raw, so this
 * checks our DEFLATE decoder against real Go output. It then compresses the same
 * raw payload with our encoder and checks our own decoder reads it back.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/crypto.h"

#ifndef SLIVER_GZIP_FIXTURES
#define SLIVER_GZIP_FIXTURES "build"
#endif

static int failures = 0;

static void check(int cond, const char *what) {
  if (!cond) {
    printf("FAIL %s\n", what);
    failures++;
  }
}

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
  buf[size] = 0;
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

static void roundtrip(const char *dir, const char *name) {
  char gz_path[512];
  char raw_path[512];
  char ours_path[512];
  unsigned char *gz;
  unsigned char *raw;
  size_t gz_len = 0;
  size_t raw_len = 0;
  unsigned char *plain = NULL;
  size_t plain_len = 0;
  unsigned char *recompressed = NULL;
  size_t recompressed_len = 0;

  (void)snprintf(gz_path, sizeof(gz_path), "%s/fixture-%s.gz", dir, name);
  (void)snprintf(raw_path, sizeof(raw_path), "%s/fixture-%s.raw", dir, name);
  (void)snprintf(ours_path, sizeof(ours_path), "%s/ours-%s.gz", dir, name);

  gz = read_file(gz_path, &gz_len);
  raw = read_file(raw_path, &raw_len);
  if (gz == NULL || raw == NULL) {
    printf("SKIP %s (fixtures missing)\n", name);
    free(gz);
    free(raw);
    return;
  }

  /* Go -> C */
  if (sliver_gzip_decompress(gz, gz_len, &plain, &plain_len, 0) != 0) {
    printf("FAIL %s: cannot inflate Go fixture\n", name);
    failures++;
  } else {
    if (plain_len != raw_len || memcmp(plain, raw, raw_len) != 0) {
      printf("FAIL %s: inflated %u bytes, expected %u\n", name, (unsigned)plain_len,
             (unsigned)raw_len);
      failures++;
    }
    free(plain);
  }

  /* C -> C, and leave the artifact for the Go side to verify. */
  if (sliver_gzip_compress(raw, raw_len, &recompressed, &recompressed_len) != 0) {
    printf("FAIL %s: cannot compress\n", name);
    failures++;
  } else {
    unsigned char *back = NULL;
    size_t back_len = 0;
    if (sliver_gzip_decompress(recompressed, recompressed_len, &back, &back_len, 0) != 0 ||
        back_len != raw_len || memcmp(back, raw, raw_len) != 0) {
      printf("FAIL %s: C round-trip mismatch\n", name);
      failures++;
    }
    free(back);
    if (write_file(ours_path, recompressed, recompressed_len) != 0) {
      printf("FAIL %s: cannot write %s\n", name, ours_path);
      failures++;
    }
    free(recompressed);
  }

  free(gz);
  free(raw);
}

int main(void) {
  static const char *names[] = {"s1", "s2", "s3", "s4"};
  size_t i;

  for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    roundtrip(SLIVER_GZIP_FIXTURES, names[i]);
  }

  if (failures != 0) {
    printf("test_gzip: %d failure(s)\n", failures);
    return 1;
  }
  printf("test_gzip: PASS\n");
  return 0;
}
