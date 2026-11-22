/* src/platform/posix/fs.c - POSIX filesystem helpers. */
#define _POSIX_C_SOURCE 200809L

#include "sliver/fs.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>

static void mode_string(mode_t mode, char *out, size_t cap) {
  if (cap < 11) {
    if (cap > 0) {
      out[0] = '\0';
    }
    return;
  }
  out[0] = S_ISDIR(mode) ? 'd' : (S_ISLNK(mode) ? 'l' : '-');
  out[1] = (mode & S_IRUSR) ? 'r' : '-';
  out[2] = (mode & S_IWUSR) ? 'w' : '-';
  out[3] = (mode & S_IXUSR) ? 'x' : '-';
  out[4] = (mode & S_IRGRP) ? 'r' : '-';
  out[5] = (mode & S_IWGRP) ? 'w' : '-';
  out[6] = (mode & S_IXGRP) ? 'x' : '-';
  out[7] = (mode & S_IROTH) ? 'r' : '-';
  out[8] = (mode & S_IWOTH) ? 'w' : '-';
  out[9] = (mode & S_IXOTH) ? 'x' : '-';
  out[10] = '\0';
}

int sliver_fs_list(const char *path, sliver_dir_cb cb, void *ctx) {
  DIR *dir;
  struct dirent *de;
  const char *base = (path == NULL || path[0] == '\0') ? "." : path;

  dir = opendir(base);
  if (dir == NULL) {
    return -1;
  }
  while ((de = readdir(dir)) != NULL) {
    sliver_dir_entry_t entry;
    struct stat st;
    char full[PATH_MAX];

    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
      continue;
    }
    memset(&entry, 0, sizeof(entry));
    (void)snprintf(entry.name, sizeof(entry.name), "%s", de->d_name);
    if (snprintf(full, sizeof(full), "%s/%s", base, de->d_name) < (int)sizeof(full) &&
        lstat(full, &st) == 0) {
      entry.is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
      entry.size = (int64_t)st.st_size;
      entry.mtime = (int64_t)st.st_mtime;
      mode_string(st.st_mode, entry.mode, sizeof(entry.mode));
      if (S_ISLNK(st.st_mode)) {
        ssize_t n = readlink(full, entry.link, sizeof(entry.link) - 1);
        if (n > 0) {
          entry.link[n] = '\0';
        }
      }
    }
    if (cb(&entry, ctx) != 0) {
      break;
    }
  }
  (void)closedir(dir);
  return 0;
}

int sliver_fs_exists(const char *path) {
  struct stat st;
  if (path == NULL || path[0] == '\0') {
    return 0;
  }
  return stat(path, &st) == 0;
}

int sliver_fs_getcwd(char *buf, size_t cap) {
  if (buf == NULL || cap == 0) {
    return -1;
  }
  return getcwd(buf, cap) != NULL ? 0 : -1;
}

int sliver_fs_chdir(const char *path) {
  return chdir(path) == 0 ? 0 : -1;
}

int sliver_fs_abspath(const char *path, char *buf, size_t cap) {
  char tmp[PATH_MAX];
  char *res;
  if (path == NULL || buf == NULL) {
    return -1;
  }
  if (path[0] == '/') {
    (void)snprintf(buf, cap, "%s", path);
    return 0;
  }
  if (getcwd(tmp, sizeof(tmp)) == NULL) {
    return -1;
  }
  res = realpath(path, NULL);
  if (res != NULL) {
    (void)snprintf(buf, cap, "%s", res);
    free(res);
    return 0;
  }
  if (snprintf(buf, cap, "%s/%s", tmp, path) >= (int)cap) {
    return -1;
  }
  return 0;
}

int sliver_fs_mkdir(const char *path) {
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (mkdir(path, 0755) == 0) {
    return 0;
  }
  return errno == EEXIST ? 0 : -1;
}

static int remove_tree(const char *path) {
  struct stat st;
  if (lstat(path, &st) != 0) {
    return -1;
  }
  if (!S_ISDIR(st.st_mode)) {
    return unlink(path) == 0 ? 0 : -1;
  }
  {
    DIR *dir = opendir(path);
    struct dirent *de;
    int rc = 0;
    if (dir == NULL) {
      return -1;
    }
    while ((de = readdir(dir)) != NULL) {
      char child[PATH_MAX];
      if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
        continue;
      }
      if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >= (int)sizeof(child)) {
        continue;
      }
      if (remove_tree(child) != 0) {
        rc = -1;
      }
    }
    (void)closedir(dir);
    if (rmdir(path) != 0) {
      rc = -1;
    }
    return rc;
  }
}

int sliver_fs_remove(const char *path, int recursive, int force) {
  struct stat st;
  (void)force;
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (lstat(path, &st) != 0) {
    return -1;
  }
  if (S_ISDIR(st.st_mode) && recursive) {
    return remove_tree(path);
  }
  if (S_ISDIR(st.st_mode)) {
    return rmdir(path) == 0 ? 0 : -1;
  }
  return unlink(path) == 0 ? 0 : -1;
}


int sliver_fs_is_dir(const char *path) {
  struct stat st;
  if (path == NULL || path[0] == '\0') {
    return 0;
  }
  return (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;
}

int sliver_fs_move(const char *src, const char *dst) {
  if (src == NULL || dst == NULL) {
    return -1;
  }
  if (rename(src, dst) == 0) {
    return 0;
  }
  {
    int64_t written = 0;
    if (sliver_fs_copy(src, dst, &written) != 0) {
      return -1;
    }
    return sliver_fs_remove(src, 0, 1);
  }
}

int sliver_fs_chmod(const char *path, const char *mode, int recursive) {
  long parsed;
  char *end = NULL;
  (void)recursive;
  if (path == NULL || mode == NULL) {
    return -1;
  }
  parsed = strtol(mode, &end, 8);
  if (end == mode) {
    return -1;
  }
  return chmod(path, (mode_t)parsed) == 0 ? 0 : -1;
}

int sliver_fs_settimes(const char *path, int64_t atime, int64_t mtime) {
  struct utimbuf times;
  if (path == NULL) {
    return -1;
  }
  times.actime = (time_t)atime;
  times.modtime = (time_t)mtime;
  return utime(path, &times) == 0 ? 0 : -1;
}

