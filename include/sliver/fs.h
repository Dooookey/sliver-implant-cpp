/* sliver/fs.h - minimal filesystem surface used by the RPC handlers. */
#ifndef SLIVER_FS_H
#define SLIVER_FS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  char name[256];
  int is_dir;
  int64_t size;
  int64_t mtime;    /* unix seconds */
  char mode[16];    /* "drwxrwxrwx" / "-rw-rw-rw-" style, as Go reports it */
  char link[256];   /* symlink target when available, else empty */
} sliver_dir_entry_t;

typedef int (*sliver_dir_cb)(const sliver_dir_entry_t *entry, void *ctx);

/* Lists `path` (empty or "." = current directory). The callback is invoked once
 * per entry; "." and ".." are skipped like Go's os.ReadDir. Returns 0 on
 * success, -1 when the directory cannot be opened. */
int sliver_fs_list(const char *path, sliver_dir_cb cb, void *ctx);

int sliver_fs_exists(const char *path);
int sliver_fs_is_dir(const char *path);
int sliver_fs_getcwd(char *buf, size_t cap);
int sliver_fs_chdir(const char *path);
/* Creates one directory level. Returns 0 on success (existing dir counts). */
int sliver_fs_mkdir(const char *path);
/* Removes a file or directory. recursive walks subdirectories; force ignores
 * read-only/permission quirks where the platform allows it. */
int sliver_fs_remove(const char *path, int recursive, int force);

/* --- chunked file IO (download/upload) ---------------------------------- */
#include "sliver/proto.h"

/* Appends up to max bytes starting at `start` to `out`. */
int sliver_fs_read_chunk(const char *path, int64_t start, int64_t max, sliver_buf_t *out);
/* Appends data to path; `overwrite` truncates the file first. */
int sliver_fs_write_chunk(const char *path, const void *data, size_t len, int overwrite);
int64_t sliver_fs_size(const char *path);

/* --- P1.2 file operations ---------------------------------------------- */
int sliver_fs_copy(const char *src, const char *dst, int64_t *written);
/* errno of the last sliver_fs_copy failure. */
int sliver_fs_last_error(void);
int sliver_fs_move(const char *src, const char *dst);
int sliver_fs_chmod(const char *path, const char *mode, int recursive);
int sliver_fs_settimes(const char *path, int64_t atime, int64_t mtime);
/* Expands a possibly relative path to absolute form (best effort). */
int sliver_fs_abspath(const char *path, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_FS_H */



