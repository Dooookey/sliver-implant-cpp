/* src/core/fileio.c - portable file read/write used by download/upload. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/fs.h"
#include "sliver/proto.h"

int sliver_fs_read_chunk(const char *path, int64_t start, int64_t max, sliver_buf_t *out) {
  FILE *f;
  long pos;
  size_t want;
  uint8_t *tmp;
  size_t got;

  if (path == NULL || out == NULL || out->failed) {
    return -1;
  }
  f = fopen(path, "rb");
  if (f == NULL) {
    return -1;
  }
  if (max <= 0) {
    max = 64 * 1024;
  }
  if (start > 0) {
    if (fseek(f, (long)start, SEEK_SET) != 0) {
      (void)fclose(f);
      return -1;
    }
  }
  (void)pos;
  want = (size_t)max;
  tmp = (uint8_t *)malloc(want);
  if (tmp == NULL) {
    (void)fclose(f);
    return -1;
  }
  got = fread(tmp, 1, want, f);
  (void)fclose(f);
  if (got == 0) {
    free(tmp);
    return 0;
  }
  if (sliver_buf_append(out, tmp, got) != 0) {
    free(tmp);
    return -1;
  }
  free(tmp);
  return 0;
}

int sliver_fs_write_chunk(const char *path, const void *data, size_t len, int overwrite) {
  FILE *f;
  if (path == NULL) {
    return -1;
  }
  f = fopen(path, overwrite ? "wb" : "ab");
  if (f == NULL) {
    return -1;
  }
  if (len != 0 && fwrite(data, 1, len, f) != len) {
    (void)fclose(f);
    return -1;
  }
  if (fclose(f) != 0) {
    return -1;
  }
  return 0;
}
int64_t sliver_fs_size(const char *path) {
  FILE *f;
  long size;
  if (path == NULL) {
    return -1;
  }
  f = fopen(path, "rb");
  if (f == NULL) {
    return -1;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    (void)fclose(f);
    return -1;
  }
  size = ftell(f);
  (void)fclose(f);
  return size < 0 ? -1 : (int64_t)size;
}
