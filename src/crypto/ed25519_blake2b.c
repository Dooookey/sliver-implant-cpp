/* src/crypto/ed25519_blake2b.c - Ed25519 (SHA-512) and BLAKE2b.
 *
 * Ed25519: orlp/ed25519 (ref10 style, BSD-2) - this is the variant minisign and
 * the Sliver envelope signatures use (Ed25519 over SHA-512). monocypher's
 * crypto_eddsa_* implements EdDSA over BLAKE2b instead, which is *not*
 * compatible, so it is only used for BLAKE2b here.
 */
#include "sliver/crypto.h"

#include <string.h>

#include "ed25519.h"
#include "monocypher.h"

int sliver_blake2b(const void *data, size_t len, unsigned char *out, size_t out_len) {
  if (out == NULL || out_len == 0 || out_len > 64 || (data == NULL && len != 0)) {
    return -1;
  }
  /* Monocypher supports 1..64 byte digests; Sliver needs 32 (key ids) and 64. */
  crypto_blake2b(out, out_len, (const uint8_t *)data, len);
  return 0;
}

int sliver_ed25519_public_from_seed(const unsigned char seed[32],
                                    unsigned char public_key[SLIVER_ED25519_PK_LEN]) {
  unsigned char secret_key[64];
  if (seed == NULL || public_key == NULL) {
    return -1;
  }
  ed25519_create_keypair(public_key, secret_key, seed);
  sliver_secure_zero(secret_key, sizeof(secret_key));
  return 0;
}

int sliver_ed25519_sign(const unsigned char seed[32], const void *msg, size_t len,
                        unsigned char sig[SLIVER_ED25519_SIG_LEN]) {
  unsigned char secret_key[64];
  unsigned char public_key[32];
  if (seed == NULL || sig == NULL || (msg == NULL && len != 0)) {
    return -1;
  }
  ed25519_create_keypair(public_key, secret_key, seed);
  ed25519_sign(sig, (const unsigned char *)msg, len, public_key, secret_key);
  sliver_secure_zero(secret_key, sizeof(secret_key));
  sliver_secure_zero(public_key, sizeof(public_key));
  return 0;
}

int sliver_ed25519_verify(const unsigned char public_key[SLIVER_ED25519_PK_LEN],
                          const void *msg, size_t len,
                          const unsigned char sig[SLIVER_ED25519_SIG_LEN]) {
  if (public_key == NULL || sig == NULL || (msg == NULL && len != 0)) {
    return -1;
  }
  return ed25519_verify(sig, (const unsigned char *)msg, len, public_key) == 1 ? 0 : -1;
}

void sliver_secure_zero(void *buf, size_t len) {
  if (buf != NULL && len != 0) {
    crypto_wipe(buf, len);
  }
}
