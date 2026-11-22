/* src/crypto/crypto_mbedtls.c - mbedTLS backed primitives. */
#include "sliver/crypto.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/chachapoly.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "psa/crypto.h"

static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_entropy_context g_entropy;
static int g_drbg_ready = 0;

static int drbg_init(void) {
  if (g_drbg_ready) {
    return 0;
  }
  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_drbg);
  {
    static const char pers[] = "sliver-implant";
    int rc = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                   (const unsigned char *)pers, sizeof(pers) - 1);
    if (rc != 0) {
      mbedtls_ctr_drbg_free(&g_drbg);
      mbedtls_entropy_free(&g_entropy);
      return -1;
    }
  }
  if (psa_crypto_init() != PSA_SUCCESS) {
    return -1;
  }
  g_drbg_ready = 1;
  return 0;
}

int sliver_random_bytes(void *buf, size_t len) {
  if (buf == NULL && len != 0) {
    return -1;
  }
  if (drbg_init() != 0) {
    return -1;
  }
  return mbedtls_ctr_drbg_random(&g_drbg, (unsigned char *)buf, len) == 0 ? 0 : -1;
}

int sliver_sha256(const void *data, size_t len, unsigned char out[SLIVER_SHA256_LEN]) {
  if (out == NULL || (data == NULL && len != 0)) {
    return -1;
  }
  return mbedtls_sha256((const unsigned char *)data, len, out, 0) == 0 ? 0 : -1;
}

int sliver_hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                       unsigned char out[SLIVER_SHA256_LEN]) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == NULL || out == NULL) {
    return -1;
  }
  return mbedtls_md_hmac(md, (const unsigned char *)key, key_len,
                         (const unsigned char *)data, data_len, out) == 0
             ? 0
             : -1;
}

int sliver_hkdf_sha256(const void *salt, size_t salt_len,
                       const void *ikm, size_t ikm_len,
                       const void *info, size_t info_len,
                       void *out, size_t out_len) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == NULL || out == NULL) {
    return -1;
  }
  return mbedtls_hkdf(md,
                      (const unsigned char *)salt, salt_len,
                      (const unsigned char *)ikm, ikm_len,
                      (const unsigned char *)info, info_len,
                      (unsigned char *)out, out_len) == 0
             ? 0
             : -1;
}

int sliver_chachapoly_seal(const unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN],
                           const unsigned char nonce[SLIVER_CHACHAPOLY_NONCE_LEN],
                           const void *aad, size_t aad_len,
                           const void *plaintext, size_t plaintext_len,
                           unsigned char *out) {
  mbedtls_chachapoly_context ctx;
  int rc;
  if (key == NULL || nonce == NULL || out == NULL) {
    return -1;
  }
  mbedtls_chachapoly_init(&ctx);
  rc = mbedtls_chachapoly_setkey(&ctx, key);
  if (rc == 0) {
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx, plaintext_len, nonce,
                                            (const unsigned char *)aad, aad_len,
                                            (const unsigned char *)plaintext,
                                            out, out + plaintext_len);
  }
  mbedtls_chachapoly_free(&ctx);
  return rc == 0 ? 0 : -1;
}

int sliver_chachapoly_open(const unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN],
                           const unsigned char nonce[SLIVER_CHACHAPOLY_NONCE_LEN],
                           const void *aad, size_t aad_len,
                           const void *ciphertext, size_t ciphertext_len,
                           unsigned char *out) {
  mbedtls_chachapoly_context ctx;
  int rc;
  size_t plain_len;
  if (key == NULL || nonce == NULL || out == NULL ||
      ciphertext_len < SLIVER_CHACHAPOLY_TAG_LEN) {
    return -1;
  }
  plain_len = ciphertext_len - SLIVER_CHACHAPOLY_TAG_LEN;
  mbedtls_chachapoly_init(&ctx);
  rc = mbedtls_chachapoly_setkey(&ctx, key);
  if (rc == 0) {
    rc = mbedtls_chachapoly_auth_decrypt(&ctx, plain_len, nonce,
                                         (const unsigned char *)aad, aad_len,
                                         (const unsigned char *)ciphertext + plain_len,
                                         (const unsigned char *)ciphertext, out);
  }
  mbedtls_chachapoly_free(&ctx);
  return rc == 0 ? 0 : -1;
}

/* --- X25519 via PSA (mbedTLS 3.6 builtin PSA knows Montgomery curves, the raw
 * ECP API does not expose them). Keys are 32 byte little endian, matching
 * RFC 7748 and the age format. */
static int import_montgomery(const unsigned char secret[32], psa_key_id_t *key_id) {
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_status_t st;

  if (drbg_init() != 0) {
    return -1;
  }
  psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
  psa_set_key_bits(&attr, 255);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
  psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
  st = psa_import_key(&attr, secret, 32, key_id);
  psa_reset_key_attributes(&attr);
  return st == PSA_SUCCESS ? 0 : -1;
}

int sliver_x25519_keypair(unsigned char secret[SLIVER_X25519_LEN],
                          unsigned char public_key[SLIVER_X25519_LEN]) {
  psa_key_id_t key_id = 0;
  size_t olen = 0;
  int rc = -1;

  if (secret == NULL || public_key == NULL) {
    return -1;
  }
  if (sliver_random_bytes(secret, 32) != 0) {
    return -1;
  }
  if (import_montgomery(secret, &key_id) != 0) {
    return -1;
  }
  if (psa_export_public_key(key_id, public_key, 32, &olen) == PSA_SUCCESS && olen == 32) {
    rc = 0;
  }
  psa_destroy_key(key_id);
  return rc;
}

int sliver_x25519_shared(const unsigned char secret[SLIVER_X25519_LEN],
                         const unsigned char peer_public[SLIVER_X25519_LEN],
                         unsigned char shared[SLIVER_X25519_LEN]) {
  psa_key_id_t key_id = 0;
  size_t olen = 0;
  int rc = -1;

  if (secret == NULL || peer_public == NULL || shared == NULL) {
    return -1;
  }
  if (import_montgomery(secret, &key_id) != 0) {
    return -1;
  }
  if (psa_raw_key_agreement(PSA_ALG_ECDH, key_id, peer_public, 32, shared, 32, &olen) ==
          PSA_SUCCESS &&
      olen == 32) {
    rc = 0;
  }
  psa_destroy_key(key_id);
  return rc;
}

