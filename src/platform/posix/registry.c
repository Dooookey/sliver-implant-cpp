/* POSIX stub: the registry is Windows-only, the handlers answer with an error. */
#include "sliver/registry.h"

int sliver_reg_read(const char *hive, const char *path, const char *key, char *value_out,
                    size_t value_cap, uint8_t *binary_out, size_t binary_cap, size_t *binary_len,
                    uint32_t *type_out) {
  (void)hive; (void)path; (void)key; (void)value_out; (void)value_cap; (void)binary_out;
  (void)binary_cap; (void)binary_len; (void)type_out;
  return -1;
}

int sliver_reg_write(const char *hive, const char *path, const char *key, uint32_t type,
                     const char *string_value, const uint8_t *bytes, size_t bytes_len,
                     uint32_t dword, uint64_t qword) {
  (void)hive; (void)path; (void)key; (void)type; (void)string_value; (void)bytes;
  (void)bytes_len; (void)dword; (void)qword;
  return -1;
}

int sliver_reg_create(const char *hive, const char *path, const char *key) {
  (void)hive; (void)path; (void)key;
  return -1;
}

int sliver_reg_delete(const char *hive, const char *path, const char *key) {
  (void)hive; (void)path; (void)key;
  return -1;
}

int sliver_reg_subkeys(const char *hive, const char *path, char (*names)[256], int max) {
  (void)hive; (void)path; (void)names; (void)max;
  return -1;
}

int sliver_reg_values(const char *hive, const char *path, char (*names)[256], int max) {
  (void)hive; (void)path; (void)names; (void)max;
  return -1;
}
