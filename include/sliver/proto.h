/* sliver/proto.h - minimal protobuf runtime and the Sliver messages the
 * implant needs first (Envelope, Register, Ping).
 *
 * Only the proto3 subset Sliver uses: varint, length delimited, fixed 32/64 if
 * ever needed. Unknown fields are skipped, so a newer server cannot break the
 * implant.
 */
#ifndef SLIVER_PROTO_H
#define SLIVER_PROTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- growable output buffer -------------------------------------------- */
typedef struct {
  uint8_t *data;
  size_t len;
  size_t cap;
  int failed;
} sliver_buf_t;

void sliver_buf_init(sliver_buf_t *b);
void sliver_buf_free(sliver_buf_t *b);
/* Appends raw bytes (no protobuf tag). */
int sliver_buf_append(sliver_buf_t *b, const void *data, size_t len);
int sliver_buf_put_varint(sliver_buf_t *b, uint64_t value);
int sliver_buf_put_tag(sliver_buf_t *b, uint32_t field, uint32_t wire_type);
int sliver_buf_put_bytes(sliver_buf_t *b, uint32_t field, const void *data, size_t len);
int sliver_buf_put_string(sliver_buf_t *b, uint32_t field, const char *s);
int sliver_buf_put_uint64(sliver_buf_t *b, uint32_t field, uint64_t value);
int sliver_buf_put_uint32(sliver_buf_t *b, uint32_t field, uint32_t value);
int sliver_buf_put_int64(sliver_buf_t *b, uint32_t field, int64_t value);
int sliver_buf_put_int32(sliver_buf_t *b, uint32_t field, int32_t value);
int sliver_buf_put_bool(sliver_buf_t *b, uint32_t field, int value);

/* --- input reader ------------------------------------------------------ */
typedef struct {
  const uint8_t *data;
  size_t len;
  size_t pos;
  int failed;
} sliver_reader_t;

void sliver_reader_init(sliver_reader_t *r, const void *data, size_t len);
int sliver_reader_next(sliver_reader_t *r, uint32_t *field, uint32_t *wire_type);
int sliver_reader_varint(sliver_reader_t *r, uint64_t *value);
int sliver_reader_bytes(sliver_reader_t *r, const uint8_t **data, size_t *len);
/* Copies a length delimited field into out (NUL terminated when cap allows). */
int sliver_reader_string(sliver_reader_t *r, char *out, size_t cap);
int sliver_reader_skip(sliver_reader_t *r, uint32_t wire_type);

/* --- Envelope ---------------------------------------------------------- */
typedef struct {
  int64_t id;
  uint32_t type;
  const uint8_t *data;
  size_t data_len;
  int unknown_message_type;
} sliver_envelope_t;

int sliver_envelope_encode(sliver_buf_t *out, int64_t id, uint32_t type,
                           const void *data, size_t data_len);
int sliver_envelope_decode(const void *data, size_t len, sliver_envelope_t *out);

/* --- Register ---------------------------------------------------------- */
#define SLIVER_REGISTER_MAX_STR 128

typedef struct {
  char name[SLIVER_REGISTER_MAX_STR];
  char hostname[SLIVER_REGISTER_MAX_STR];
  char uuid[SLIVER_REGISTER_MAX_STR];
  char username[SLIVER_REGISTER_MAX_STR];
  char uid[SLIVER_REGISTER_MAX_STR];
  char gid[SLIVER_REGISTER_MAX_STR];
  char os[16];
  char arch[16];
  int32_t pid;
  char filename[512];
  char active_c2[256];
  char version[32];
  int64_t reconnect_interval;
  char proxy_url[256];
  char config_id[64];
  int64_t peer_id;
  char locale[32];
  uint64_t capabilities;
} sliver_register_t;

int sliver_register_encode(sliver_buf_t *out, const sliver_register_t *reg);
int sliver_register_decode(const void *data, size_t len, sliver_register_t *out);

/* --- Ping -------------------------------------------------------------- */
int sliver_ping_encode(sliver_buf_t *out, int32_t nonce);
int sliver_ping_decode_nonce(const void *data, size_t len, int32_t *nonce);

/* --- Ls / LsReq (P1.1) -------------------------------------------------- */
#define SLIVER_FILE_MAX_NAME 256
#define SLIVER_FILE_MAX_LINK 256

typedef struct {
  char name[SLIVER_FILE_MAX_NAME];
  int is_dir;
  int64_t size;
  int64_t mtime;
  char mode[16];
  char link[SLIVER_FILE_MAX_LINK];
  char uid[16];
  char gid[16];
} sliver_file_info_t;

/* LsReq.Path (field 1); missing path yields an empty string. */
int sliver_ls_req_decode(const void *data, size_t len, char *path, size_t cap);
/* Ls{Path=1, Exists=2, Files=3, Response=9}. An empty commonpb.Response is
 * always emitted so the client's GetResponse() is non-nil. */
int sliver_ls_encode(sliver_buf_t *out, const char *path, int exists,
                     const sliver_file_info_t *files, size_t count);
/* Pwd{Path=1, Response=9}. */
int sliver_pwd_encode(sliver_buf_t *out, const char *path);
/* PwdReq has no fields of interest; it only carries commonpb.Request (field 9).
 * Copies that nested blob when present. */
int sliver_request_field(const void *data, size_t len, const uint8_t **out, size_t *out_len);

/* --- message type ids (protobuf/sliverpb/constants.go, append only) ---- */
#define SLIVER_MSG_REGISTER 1u
#define SLIVER_MSG_PING 3u
#define SLIVER_MSG_LS_REQ 5u
#define SLIVER_MSG_LS 6u
#define SLIVER_MSG_PWD_REQ 12u
#define SLIVER_MSG_PWD 13u
#define SLIVER_MSG_BEACON_REGISTER 93u
#define SLIVER_MSG_BEACON_TASKS 94u

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_PROTO_H */
