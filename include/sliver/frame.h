/* sliver/frame.h - Sliver's signed envelope frame (mtls / wireguard transports).
 *
 * Wire format (see implant/sliver/transports/mtls/mtls.go):
 *
 *   [74B raw minisign signature][u32 LE length][protobuf Envelope]
 *
 * The signature algorithm is Ed25519 over the protobuf bytes, with a private
 * key derived from the injected age private key:
 *
 *   seed   = SHA256("env-signing-v1:" + agePrivateKeyString)
 *   pub    = Ed25519(seed).public
 *   key id = LE64(BLAKE2b-256(pub)[:8])
 *   raw sig = u16 LE 0x6445 | u64 LE key id | 64B signature
 *
 * Incoming frames carry the *server's* minisign signature and are verified with
 * the injected server minisign public key text.
 */
#ifndef SLIVER_FRAME_H
#define SLIVER_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLIVER_FRAME_SIG_LEN 74
#define SLIVER_FRAME_MAX_ENVELOPE (8u * 1024u * 1024u) /* sanity bound, protocol allows 512 MiB */

typedef struct {
  unsigned char seed[32];
  unsigned char public_key[32];
  uint64_t key_id;
  int ready;
} sliver_frame_signer_t;

typedef long (*sliver_io_read_fn)(void *ctx, void *buf, size_t len);
typedef long (*sliver_io_write_fn)(void *ctx, const void *buf, size_t len);

/* Derives the signing key from the age private key string injected at build
 * time (AGE-SECRET-KEY-1...). Returns 0 on success. */
int sliver_frame_signer_init(sliver_frame_signer_t *signer, const char *age_private_key);

/* Encodes [sig][len][envelope] into out (which is reset first). */
int sliver_frame_encode(const sliver_frame_signer_t *signer,
                        const void *envelope, size_t envelope_len,
                        sliver_buf_t *out);

/* Writes a signed frame to a stream. Returns 0 on success. */
int sliver_frame_write(sliver_frame_signer_t *signer, sliver_io_write_fn write_fn, void *ctx,
                       const void *envelope, size_t envelope_len);

/* Reads one signed frame from a stream into env_out (caller frees env_out->data).
 * server_pubkey_text is the two line minisign public key injected at build time.
 * Returns 0 on success, -1 on I/O failure, -2 on signature/format failure. */
int sliver_frame_read(const char *server_pubkey_text, sliver_io_read_fn read_fn, void *ctx,
                      sliver_buf_t *env_out);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_FRAME_H */
