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
int sliver_fs_getcwd(char *buf, size_t cap);
int sliver_fs_chdir(const char *path);
/* Creates one directory level. Returns 0 on success (existing dir counts). */
int sliver_fs_mkdir(const char *path);
/* Removes a file or directory. recursive walks subdirectories; force ignores
 * read-only/permission quirks where the platform allows it. */
int sliver_fs_remove(const char *path, int recursive, int force);
/* Expands a possibly relative path to absolute form (best effort). */
int sliver_fs_abspath(const char *path, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_FS_H */
