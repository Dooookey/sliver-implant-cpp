/* sliver/registry.h - Windows registry access used by the RPC layer. */
#ifndef SLIVER_REGISTRY_H
#define SLIVER_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#include "sliver/proto.h"

/* Sliver's RegistryType enum. */
#define SLIVER_REG_UNKNOWN 0u
#define SLIVER_REG_BINARY 1u
#define SLIVER_REG_STRING 2u
#define SLIVER_REG_DWORD 3u
#define SLIVER_REG_QWORD 4u

/* Reads Key under Hive\Path. String values go to value_out, everything else to
 * binary_out (length in *binary_len). *type_out receives the Sliver type. */
int sliver_reg_read(const char *hive, const char *path, const char *key, char *value_out,
                    size_t value_cap, uint8_t *binary_out, size_t binary_cap, size_t *binary_len,
                    uint32_t *type_out);

/* Writes Key with the given Sliver type. */
int sliver_reg_write(const char *hive, const char *path, const char *key, uint32_t type,
                     const char *string_value, const uint8_t *bytes, size_t bytes_len,
                     uint32_t dword, uint64_t qword);

int sliver_reg_create(const char *hive, const char *path, const char *key);
/* Deletes the value Key first; falls back to deleting the subkey. */
int sliver_reg_delete(const char *hive, const char *path, const char *key);

/* Both fill caller arrays and return the count (-1 on failure). */
int sliver_reg_subkeys(const char *hive, const char *path, char (*names)[256], int max);
int sliver_reg_values(const char *hive, const char *path, char (*names)[256], int max);

/* Decoded registry request: Hive=1, Path=2, Key=3, Hostname=4, StringValue=5,
 * ByteValue=6, DWordValue=7, QWordValue=8, Type=10. */
typedef struct {
  char hive[32];
  char path[512];
  char key[512];
  char hostname[256];
  char string_value[1024];
  uint8_t byte_value[4096];
  size_t byte_len;
  uint32_t dword;
  uint64_t qword;
  uint32_t type;
} sliver_reg_req_t;

int sliver_reg_req_decode(const void *data, size_t len, sliver_reg_req_t *out);
int sliver_reg_read_encode(sliver_buf_t *out, const char *value, const uint8_t *binary,
                           size_t binary_len, uint32_t type, const char *err);
int sliver_reg_names_encode(sliver_buf_t *out, char (*names)[256], int count, const char *err);

#endif

