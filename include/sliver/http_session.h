/* sliver/http_session.h - Sliver HTTP(S) C2 session layer.
 *
 * Wraps the real listener's session handshake (age key exchange -> cookie) and
 * its encoder + CipherContext payload format, so a scheduler can keep using plain
 * envelopes.
 */
#ifndef SLIVER_HTTP_SESSION_H
#define SLIVER_HTTP_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "sliver/crypto.h"
#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  char host[256];
  uint16_t port;
  int use_tls;
  char base_path[512];
  /* The listener sets a cookie whose NAME is random per response
   * (server/c2/http.go getCookieName), so remember whatever it sent last. */
  char cookie_name[128];
  char cookie_value[128];
  int have_cookie;
  unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN];
  long long poll_timeout_ns;
  int timeout_ms; /* current request timeout (long poll for GET) */
  int established;
} sliver_http_session_t;

int sliver_http_session_init(sliver_http_session_t *s, const char *host, uint16_t port,
                             int use_tls, const char *base_path);

/* One HTTP request/response. Exposed for tests: returns 0 on a complete response
 * and fills status_out / resp_body (caller frees). */
int sliver_http_session_exchange(sliver_http_session_t *s, const char *method,
                                 const char *path, const void *body, size_t body_len,
                                 int *status_out, unsigned char **resp_body,
                                 size_t *resp_len);

/* HTTPSessionInit + age key exchange + POST; 0 on success. */
int sliver_http_session_establish(sliver_http_session_t *s);

/* Sends one envelope (POST, expects 202/204). */
int sliver_http_session_send(sliver_http_session_t *s, const void *envelope, size_t len);

/* Polls: 0 = envelope in env_out, 1 = idle (204), -1 = stale/failed. */
int sliver_http_session_recv(sliver_http_session_t *s, sliver_buf_t *env_out);

void sliver_http_session_close(sliver_http_session_t *s);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_HTTP_SESSION_H */
