/* src/platform/win32/fs.c - Windows filesystem helpers (Win32 only). */
#include "sliver/fs.h"

#include <stdio.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static void mode_string(DWORD attrs, int is_dir, char *out, size_t cap) {
  /* Go reports "drwxrwxrwx" for directories and "-rw-rw-rw-" for files on
   * Windows (permission bits are synthesized). */
  if (is_dir) {
    (void)snprintf(out, cap, "drwxrwxrwx");
  } else if ((attrs & FILE_ATTRIBUTE_READONLY) != 0) {
    (void)snprintf(out, cap, "-r--r--r--");
  } else {
    (void)snprintf(out, cap, "-rw-rw-rw-");
  }
}

static int64_t filetime_to_unix(const FILETIME *ft) {
  ULARGE_INTEGER v;
  v.LowPart = ft->dwLowDateTime;
  v.HighPart = ft->dwHighDateTime;
  /* 100ns intervals since 1601-01-01 -> seconds since 1970-01-01 */
  return (int64_t)((v.QuadPart / 10000000ULL) - 11644473600ULL);
}

int sliver_fs_list(const char *path, sliver_dir_cb cb, void *ctx) {
  char pattern[MAX_PATH * 2];
  WIN32_FIND_DATAA data;
  HANDLE h;
  const char *base = (path == NULL || path[0] == '\0') ? "." : path;

  if (snprintf(pattern, sizeof(pattern), "%s%s*", base,
               (base[strlen(base) - 1] == '\\' || base[strlen(base) - 1] == '/') ? "" : "\\") >=
      (int)sizeof(pattern)) {
    return -1;
  }
  h = FindFirstFileA(pattern, &data);
  if (h == INVALID_HANDLE_VALUE) {
    return -1;
  }
  do {
    sliver_dir_entry_t entry;
    if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0) {
      continue;
    }
    memset(&entry, 0, sizeof(entry));
    (void)snprintf(entry.name, sizeof(entry.name), "%s", data.cFileName);
    entry.is_dir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    entry.size = ((int64_t)data.nFileSizeHigh << 32) | (int64_t)data.nFileSizeLow;
    entry.mtime = filetime_to_unix(&data.ftLastWriteTime);
    mode_string(data.dwFileAttributes, entry.is_dir, entry.mode, sizeof(entry.mode));
    if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
      (void)snprintf(entry.link, sizeof(entry.link), "%s", "");
    }
    if (cb(&entry, ctx) != 0) {
      break;
    }
  } while (FindNextFileA(h, &data));
  (void)FindClose(h);
  return 0;
}

int sliver_fs_exists(const char *path) {
  DWORD attrs;
  if (path == NULL || path[0] == '\0') {
    return 0;
  }
  attrs = GetFileAttributesA(path);
  return attrs != INVALID_FILE_ATTRIBUTES;
}

int sliver_fs_getcwd(char *buf, size_t cap) {
  DWORD n;
  if (buf == NULL || cap == 0) {
    return -1;
  }
  n = GetCurrentDirectoryA((DWORD)cap, buf);
  if (n == 0 || n >= cap) {
    return -1;
  }
  return 0;
}

int sliver_fs_chdir(const char *path) {
  return SetCurrentDirectoryA(path) ? 0 : -1;
}

int sliver_fs_abspath(const char *path, char *buf, size_t cap) {
  DWORD n;
  if (path == NULL || buf == NULL) {
    return -1;
  }
  n = GetFullPathNameA(path, (DWORD)cap, buf, NULL);
  if (n == 0 || n >= cap) {
    return -1;
  }
  return 0;
}
