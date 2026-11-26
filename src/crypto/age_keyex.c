/* src/crypto/age_keyex.c - Sliver's implant->server key exchange.
 *
 * Mirrors implant/sliver/cryptography/crypto.go AgeKeyExToServer and the
 * matching server check in server/cryptography/cryptography.go
 * AgeKeyExFromImplant:
 *
 *   privateDigest = SHA256(peer.private)                     (over the string)
 *   mac           = HMAC-SHA256(privateDigest, plaintext)
 *   ciphertext    = age_encrypt(server.public, mac || plaintext)
 *   message       = SHA256(peer.public) || ciphertext
 *
 * The server strips the 32 byte prefix to identify the implant, decrypts with its
 * own age identity, recomputes the HMAC and compares it in constant time.
 */
#include "sliver/crypto.h"
#include "sliver/config.h"

#include <stdlib.h>
#include <string.h>

#define SLIVER_AGE_DIGEST_LEN 32

/* X25519 public key = scalar * base point (same trick as age.c). */
static int public_from_secret(const unsigned char secret[32], unsigned char public_key[32]) {
  unsigned char base[32];
  memset(base, 0, sizeof(base));
  base[0] = 9;
  return sliver_x25519_shared(secret, base, public_key);
}

/* bech32-decode the "AGE-SECRET-KEY-1..." identity into a raw X25519 secret. */
static int identity_to_secret(const char *identity, unsigned char secret[32]) {
  size_t len = 32;
  if (sliver_bech32_decode(identity, secret, &len) != 0 || len != 32) {
    return -1;
  }
  return 0;
}

int sliver_age_peer_public(const char *identity, char *out, size_t out_cap) {
  unsigned char secret[32];
  unsigned char public_key[32];
  if (identity == NULL || out == NULL || out_cap < 4) {
    return -1;
  }
  if (identity_to_secret(identity, secret) != 0) {
    return -1;
  }
  if (public_from_secret(secret, public_key) != 0) {
    return -1;
  }
  if (sliver_bech32_encode("age", public_key, sizeof(public_key), out, out_cap) != 0) {
    return -1;
  }
  sliver_secure_zero(secret, sizeof(secret));
  return 0;
}

int sliver_age_keyex_to_server(const char *server_age_public, const char *peer_public,
                               const char *peer_private, const void *plaintext,
                               size_t plaintext_len, unsigned char **out, size_t *out_len) {
  unsigned char private_digest[SLIVER_AGE_DIGEST_LEN];
  unsigned char public_digest[SLIVER_AGE_DIGEST_LEN];
  unsigned char mac[SLIVER_AGE_DIGEST_LEN];
  unsigned char *payload = NULL;
  unsigned char *ciphertext = NULL;
  size_t ciphertext_len = 0;
  unsigned char *msg = NULL;
  int rc = -1;

  if (server_age_public == NULL || peer_public == NULL || peer_private == NULL ||
      out == NULL || out_len == NULL || (plaintext == NULL && plaintext_len != 0)) {
    return -1;
  }
  *out = NULL;
  *out_len = 0;

  if (sliver_sha256(peer_private, strlen(peer_private), private_digest) != 0) {
    return -1;
  }
  if (sliver_hmac_sha256(private_digest, sizeof(private_digest), plaintext, plaintext_len,
                         mac) != 0) {
    sliver_secure_zero(private_digest, sizeof(private_digest));
    return -1;
  }
  sliver_secure_zero(private_digest, sizeof(private_digest));

  payload = (unsigned char *)malloc(SLIVER_AGE_DIGEST_LEN + plaintext_len);
  if (payload == NULL) {
    return -1;
  }
  memcpy(payload, mac, SLIVER_AGE_DIGEST_LEN);
  if (plaintext_len != 0) {
    memcpy(payload + SLIVER_AGE_DIGEST_LEN, plaintext, plaintext_len);
  }
  if (sliver_age_encrypt(server_age_public, payload, SLIVER_AGE_DIGEST_LEN + plaintext_len,
                         &ciphertext, &ciphertext_len) != 0) {
    free(payload);
    return -1;
  }
  sliver_secure_zero(payload, SLIVER_AGE_DIGEST_LEN + plaintext_len);
  free(payload);

  if (sliver_sha256(peer_public, strlen(peer_public), public_digest) != 0) {
    free(ciphertext);
    return -1;
  }

  msg = (unsigned char *)malloc(SLIVER_AGE_DIGEST_LEN + ciphertext_len);
  if (msg == NULL) {
    free(ciphertext);
    return -1;
  }
  memcpy(msg, public_digest, SLIVER_AGE_DIGEST_LEN);
  memcpy(msg + SLIVER_AGE_DIGEST_LEN, ciphertext, ciphertext_len);
  *out_len = SLIVER_AGE_DIGEST_LEN + ciphertext_len;

  free(ciphertext);
  *out = msg;
  rc = 0;
  return rc;
}

int sliver_age_keyex_to_server_config(const void *plaintext, size_t plaintext_len,
                                      unsigned char **out, size_t *out_len) {
  return sliver_age_keyex_to_server(
      sliver_config_secret(SLIVER_SECRET_AGE_SERVER_PUBLIC_KEY),
      sliver_config_secret(SLIVER_SECRET_PEER_PUBLIC_KEY),
      sliver_config_secret(SLIVER_SECRET_PEER_PRIVATE_KEY), plaintext, plaintext_len, out,
      out_len);
}
