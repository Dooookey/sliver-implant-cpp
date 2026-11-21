/* src/platform/posix/fs.c - POSIX filesystem helpers. */
#define _POSIX_C_SOURCE 200809L

#include "sliver/fs.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
