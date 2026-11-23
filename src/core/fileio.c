/* src/core/fileio.c - portable file read/write used by download/upload. */
#if !defined(_WIN32) && (!defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200809L)
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L /* fseeko/ftello, off_t */
#endif

#include <errno.h>
#include <stdio.h>
#include <sys/types.h> /* off_t */

#if defined(_WIN32)
#define SLIVER_FSEEK(f, off) _fseeki64((f), (long long)(off), SEEK_SET)
#define SLIVER_FSEEK_END(f)  _fseeki64((f), 0, SEEK_END)
#define SLIVER_FTELL(f)      _ftelli64((f))
#else
#define SLIVER_FSEEK(f, off) fseeko((f), (off_t)(off), SEEK_SET)
#define SLIVER_FSEEK_END(f)  fseeko((f), 0, SEEK_END)
#define SLIVER_FTELL(f)      ftello((f))
#endif
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
    if (SLIVER_FSEEK(f, start) != 0) {
      (void)fclose(f);
      return -1;
    }
  }
  (void)pos;
  /* Never allocate the caller's full cap for a small file: clamp to what is
   * actually left after `start`. */
  want = (size_t)max;
  if (want > 64 * 1024) {
    long long end = 0;
    if (SLIVER_FSEEK_END(f) == 0) {
      end = SLIVER_FTELL(f);
    }
    if (end > (long long)start) {
      long long remaining = end - (long long)start;
      if (remaining < (long long)want) {
        want = (size_t)remaining;
      }
    }
    if (SLIVER_FSEEK(f, start) != 0) {
      (void)fclose(f);
      return -1;
    }
  }
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
static int g_fs_last_error = 0;

int64_t sliver_fs_size(const char *path) {
  FILE *f;
  if (path == NULL) {
    return -1;
  }
  f = fopen(path, "rb");
  if (f == NULL) {
    return -1;
  }
  /* Seek to the end first: ftell on a freshly opened file is always 0. */
  if (SLIVER_FSEEK_END(f) != 0) {
    (void)fclose(f);
    return -1;
  }
  {
    long long end = SLIVER_FTELL(f);
    (void)fclose(f);
    return end < 0 ? -1 : (int64_t)end;
  }
}


int sliver_fs_copy(const char *src, const char *dst, int64_t *written) {
  FILE *in;
  FILE *out;
  char buf[65536];
  size_t n;
  int64_t total = 0;

  if (src == NULL || dst == NULL) {
    return -1;
  }
  in = fopen(src, "rb");
  if (in == NULL) {
    g_fs_last_error = errno;
    return -1;
  }
  out = fopen(dst, "wb");
  if (out == NULL) {
    g_fs_last_error = errno;
    (void)fclose(in);
    return -1;
  }
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (fwrite(buf, 1, n, out) != n) {
      g_fs_last_error = errno;
      (void)fclose(in);
      (void)fclose(out);
      return -1;
    }
    total += (int64_t)n;
  }
  (void)fclose(in);
  if (fclose(out) != 0) {
    g_fs_last_error = errno;
    return -1;
  }
  if (written != NULL) {
    *written = total;
  }
  return 0;
}

int sliver_fs_last_error(void) { return g_fs_last_error; }

