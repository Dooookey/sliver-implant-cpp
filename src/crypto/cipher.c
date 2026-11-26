/* src/crypto/cipher.c - Sliver's CipherContext frame.
 *
 * Mirrors implant/sliver/cryptography/crypto.go:
 *
 *   Encrypt(key, plaintext) = nonce(12 random) || AEAD_Seal(gzip(plaintext))
 *   Decrypt(key, ciphertext) = gunzip(AEAD_Open(nonce, rest))
 *
 * ChaCha20-Poly1305 with a 16 byte tag, no additional data. The replay cache and
 * the minisign envelope around it live one layer up (the HTTP channel verifies
 * the frame signature), so this file stays a pure codec.
 */
#include "sliver/crypto.h"

#include <stdlib.h>
#include <string.h>

int sliver_cipher_encrypt(const unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN],
                          const void *plaintext, size_t plaintext_len,
                          unsigned char **out, size_t *out_len) {
  unsigned char *compressed = NULL;
  size_t compressed_len = 0;
  unsigned char *frame;
  size_t frame_len;
  int rc;

  if (key == NULL || out == NULL || out_len == NULL ||
      (plaintext == NULL && plaintext_len != 0)) {
    return -1;
  }
  if (sliver_gzip_compress(plaintext, plaintext_len, &compressed, &compressed_len) != 0) {
    return -1;
  }
  frame_len = SLIVER_CHACHAPOLY_NONCE_LEN + compressed_len + SLIVER_CHACHAPOLY_TAG_LEN;
  frame = (unsigned char *)malloc(frame_len);
  if (frame == NULL) {
    free(compressed);
    return -1;
  }
  if (sliver_random_bytes(frame, SLIVER_CHACHAPOLY_NONCE_LEN) != 0) {
    free(frame);
    free(compressed);
    return -1;
  }
  rc = sliver_chachapoly_seal(key, frame, NULL, 0, compressed, compressed_len,
                              frame + SLIVER_CHACHAPOLY_NONCE_LEN);
  free(compressed);
  if (rc != 0) {
    free(frame);
    return -1;
  }
  *out = frame;
  *out_len = frame_len;
  return 0;
}

int sliver_cipher_decrypt(const unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN],
                          const void *ciphertext, size_t ciphertext_len,
                          unsigned char **out, size_t *out_len) {
  const unsigned char *frame = (const unsigned char *)ciphertext;
  unsigned char *compressed = NULL;
  size_t compressed_len;
  int rc;

  if (key == NULL || frame == NULL || out == NULL || out_len == NULL) {
    return -1;
  }
  if (ciphertext_len <= SLIVER_CHACHAPOLY_NONCE_LEN + SLIVER_CHACHAPOLY_TAG_LEN - 1) {
    return -1;
  }
  compressed_len = ciphertext_len - SLIVER_CHACHAPOLY_NONCE_LEN - SLIVER_CHACHAPOLY_TAG_LEN;
  if (compressed_len == 0) {
    compressed_len = 0;
  }
  compressed = (unsigned char *)malloc(compressed_len == 0 ? 1 : compressed_len);
  if (compressed == NULL) {
    return -1;
  }
  rc = sliver_chachapoly_open(key, frame, NULL, 0, frame + SLIVER_CHACHAPOLY_NONCE_LEN,
                              ciphertext_len - SLIVER_CHACHAPOLY_NONCE_LEN, compressed);
  if (rc != 0) {
    free(compressed);
    return -1;
  }
  rc = sliver_gzip_decompress(compressed, compressed_len, out, out_len, 0);
  free(compressed);
  return rc;
}

int sliver_cipher_derive_key(const void *data, size_t len,
                             unsigned char out[SLIVER_CHACHAPOLY_KEY_LEN]) {
  /* cryptography.deriveKeyFrom: SHA256 over the source material. */
  return sliver_sha256(data, len, out);
}
