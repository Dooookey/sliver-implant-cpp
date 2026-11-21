/* src/crypto/age.c - age v1 X25519 payload encryption (Sliver flavour).
 *
 * Sliver strips the fixed 32 byte prefix
 *   "age-encryption.org/v1\n-> X25519 "
 * from the age message and re-adds it before decrypting. Everything else is the
 * standard age v1 layout:
 *
 *   <arg b64>\n<body b64>\n--- <headerMAC b64>\n<streamNonce16><chunks...>
 *
 * References (vendored Go implementation):
 *   vendor/filippo.io/age/internal/format/format.go  header layout / 64 col wrap
 *   vendor/filippo.io/age/x25519.go                  X25519 stanza, HKDF label
 *   vendor/filippo.io/age/primitives.go              header MAC, stream key
 *   vendor/filippo.io/age/internal/stream/stream.go  nonce: BE counter + flag
 */
#include "sliver/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AGE_INTRO "age-encryption.org/v1\n"
#define AGE_STANZA_PREFIX "age-encryption.org/v1\n-> X25519 "
#define AGE_PREFIX_LEN 32
#define AGE_LABEL "age-encryption.org/v1/X25519"
#define AGE_FILE_KEY_LEN 16
#define AGE_STREAM_NONCE_LEN 16
#define AGE_CHUNK_SIZE (64 * 1024)
#define AGE_MAC_LEN 32

static const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_raw_encode(const unsigned char *in, size_t in_len, char *out) {
  size_t i = 0, o = 0;
  while (i + 2 < in_len) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    out[o++] = kB64[(v >> 18) & 63];
    out[o++] = kB64[(v >> 12) & 63];
    out[o++] = kB64[(v >> 6) & 63];
    out[o++] = kB64[v & 63];
    i += 3;
  }
  if (i + 1 == in_len) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = kB64[(v >> 18) & 63];
    out[o++] = kB64[(v >> 12) & 63];
  } else if (i + 2 == in_len) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
    out[o++] = kB64[(v >> 18) & 63];
    out[o++] = kB64[(v >> 12) & 63];
    out[o++] = kB64[(v >> 6) & 63];
  }
  out[o] = '\0';
}

static int b64_char(char c) {
  const char *p = strchr(kB64, c);
  return p == NULL ? -1 : (int)(p - kB64);
}

static int b64_raw_decode(const char *in, size_t in_len, unsigned char *out, size_t *out_len) {
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0;
  for (size_t i = 0; i < in_len; ++i) {
    char c = in[i];
    int v;
    if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
      continue;
    }
    if (c == '=') {
      break;
    }
    v = b64_char(c);
    if (v < 0) {
      return -1;
    }
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= *out_len) {
        return -1;
      }
      out[o++] = (unsigned char)((acc >> bits) & 0xff);
    }
  }
  *out_len = o;
  return 0;
}

static void stream_nonce_for(unsigned char nonce[SLIVER_CHACHAPOLY_NONCE_LEN], size_t index, int is_last) {
  memset(nonce, 0, SLIVER_CHACHAPOLY_NONCE_LEN);
  nonce[3] = (unsigned char)((index >> 56) & 0xff);
  nonce[4] = (unsigned char)((index >> 48) & 0xff);
  nonce[5] = (unsigned char)((index >> 40) & 0xff);
  nonce[6] = (unsigned char)((index >> 32) & 0xff);
  nonce[7] = (unsigned char)((index >> 24) & 0xff);
  nonce[8] = (unsigned char)((index >> 16) & 0xff);
  nonce[9] = (unsigned char)((index >> 8) & 0xff);
  nonce[10] = (unsigned char)(index & 0xff);
  nonce[11] = (unsigned char)(is_last ? 0x01 : 0x00);
}

/* X25519 public key from a secret key (multiply the base point). */
static int x25519_public_from_secret(const unsigned char secret[32], unsigned char public_key[32]) {
  unsigned char base[32];
  memset(base, 0, sizeof(base));
  base[0] = 9;
  return sliver_x25519_shared(secret, base, public_key);
}

/* Builds "<arg>\n<body>\n--- <mac>\n" (prefix already trimmed) and the MAC. */
static int build_header(const unsigned char arg[32],
                        const unsigned char body[AGE_FILE_KEY_LEN + SLIVER_CHACHAPOLY_TAG_LEN],
                        const unsigned char file_key[AGE_FILE_KEY_LEN],
                        char **out, size_t *out_len) {
  char arg_b64[64];
  char body_b64[128];
  char mac_b64[64];
  unsigned char hmac_key[32];
  unsigned char mac[AGE_MAC_LEN];
  char header_no_mac[256];
  int header_len;
  char *buf;
  size_t need;

  b64_raw_encode(arg, 32, arg_b64);
  b64_raw_encode(body, AGE_FILE_KEY_LEN + SLIVER_CHACHAPOLY_TAG_LEN, body_b64);

  if (sliver_hkdf_sha256(NULL, 0, file_key, AGE_FILE_KEY_LEN, "header", 6, hmac_key, sizeof(hmac_key)) != 0) {
    return -1;
  }
  header_len = snprintf(header_no_mac, sizeof(header_no_mac), AGE_STANZA_PREFIX "%s\n%s\n---",
                        arg_b64, body_b64);
  if (header_len < 0 || (size_t)header_len >= sizeof(header_no_mac)) {
    sliver_secure_zero(hmac_key, sizeof(hmac_key));
    return -1;
  }
  /* MAC covers the header without the MAC line (age: MarshalWithoutMAC ends at "---"). */
  if (sliver_hmac_sha256(hmac_key, sizeof(hmac_key), header_no_mac, (size_t)header_len, mac) != 0) {
    sliver_secure_zero(hmac_key, sizeof(hmac_key));
    return -1;
  }
  sliver_secure_zero(hmac_key, sizeof(hmac_key));
  b64_raw_encode(mac, sizeof(mac), mac_b64);

  need = strlen(arg_b64) + strlen(body_b64) + strlen(mac_b64) + 16;
  buf = (char *)malloc(need);
  if (buf == NULL) {
    return -1;
  }
  snprintf(buf, need, "%s\n%s\n--- %s\n", arg_b64, body_b64, mac_b64);
  *out = buf;
  *out_len = strlen(buf);
  return 0;
}

int sliver_age_encrypt(const char *recipient_public_key,
                       const void *plaintext, size_t plaintext_len,
                       unsigned char **out, size_t *out_len) {
  unsigned char recipient[32];
  unsigned char eph_sk[32], eph_pk[32];
  unsigned char shared[32], salt[64], wrap_key[32];
  unsigned char file_key[AGE_FILE_KEY_LEN];
  unsigned char body[AGE_FILE_KEY_LEN + SLIVER_CHACHAPOLY_TAG_LEN];
  unsigned char stream_nonce[AGE_STREAM_NONCE_LEN];
  unsigned char stream_key[32];
  unsigned char zero_nonce[SLIVER_CHACHAPOLY_NONCE_LEN] = {0};
  char *header = NULL;
  size_t header_len = 0, chunks, total, off, recipient_len = sizeof(recipient);
  unsigned char *msg = NULL;
  int rc = -1;

  if (recipient_public_key == NULL || out == NULL || out_len == NULL ||
      (plaintext == NULL && plaintext_len != 0)) {
    return -1;
  }
  if (sliver_bech32_decode(recipient_public_key, recipient, &recipient_len) != 0 ||
      recipient_len != 32) {
    return -1;
  }
  if (sliver_x25519_keypair(eph_sk, eph_pk) != 0) {
    return -1;
  }
  if (sliver_x25519_shared(eph_sk, recipient, shared) != 0) {
    goto cleanup;
  }
  memcpy(salt, eph_pk, 32);
  memcpy(salt + 32, recipient, 32);
  if (sliver_hkdf_sha256(shared, 32, salt, sizeof(salt), AGE_LABEL, strlen(AGE_LABEL),
                         wrap_key, sizeof(wrap_key)) != 0) {
    goto cleanup;
  }
  if (sliver_random_bytes(file_key, sizeof(file_key)) != 0) {
    goto cleanup;
  }
  if (sliver_chachapoly_seal(wrap_key, zero_nonce, NULL, 0, file_key, sizeof(file_key), body) != 0) {
    goto cleanup;
  }
  if (build_header(eph_pk, body, file_key, &header, &header_len) != 0) {
    goto cleanup;
  }
  if (sliver_random_bytes(stream_nonce, sizeof(stream_nonce)) != 0) {
    goto cleanup;
  }
  if (sliver_hkdf_sha256(file_key, sizeof(file_key), stream_nonce, sizeof(stream_nonce),
                         "payload", 7, stream_key, sizeof(stream_key)) != 0) {
    goto cleanup;
  }

  chunks = plaintext_len == 0 ? 1 : (plaintext_len + AGE_CHUNK_SIZE - 1) / AGE_CHUNK_SIZE;
  total = AGE_PREFIX_LEN + header_len + AGE_STREAM_NONCE_LEN + plaintext_len +
          chunks * SLIVER_CHACHAPOLY_TAG_LEN;
  msg = (unsigned char *)malloc(total);
  if (msg == NULL) {
    goto cleanup;
  }
  memcpy(msg, AGE_STANZA_PREFIX, AGE_PREFIX_LEN);
  memcpy(msg + AGE_PREFIX_LEN, header, header_len);
  off = AGE_PREFIX_LEN + header_len;
  memcpy(msg + off, stream_nonce, AGE_STREAM_NONCE_LEN);
  off += AGE_STREAM_NONCE_LEN;

  for (size_t i = 0; i < chunks; ++i) {
    unsigned char nonce[SLIVER_CHACHAPOLY_NONCE_LEN];
    size_t chunk_off = i * AGE_CHUNK_SIZE;
    size_t chunk_len = plaintext_len - chunk_off;
    if (chunk_len > AGE_CHUNK_SIZE) {
      chunk_len = AGE_CHUNK_SIZE;
    }
    stream_nonce_for(nonce, i, i == chunks - 1);
    if (sliver_chachapoly_seal(stream_key, nonce, NULL, 0,
                               (const unsigned char *)plaintext + chunk_off, chunk_len,
                               msg + off) != 0) {
      goto cleanup;
    }
    off += chunk_len + SLIVER_CHACHAPOLY_TAG_LEN;
  }

  memmove(msg, msg + AGE_PREFIX_LEN, off - AGE_PREFIX_LEN);
  *out = msg;
  *out_len = off - AGE_PREFIX_LEN;
  msg = NULL;
  rc = 0;

cleanup:
  free(header);
  free(msg);
  sliver_secure_zero(eph_sk, sizeof(eph_sk));
  sliver_secure_zero(shared, sizeof(shared));
  sliver_secure_zero(wrap_key, sizeof(wrap_key));
  sliver_secure_zero(file_key, sizeof(file_key));
  sliver_secure_zero(stream_key, sizeof(stream_key));
  return rc;
}

int sliver_age_decrypt(const char *identity,
                       const void *ciphertext, size_t ciphertext_len,
                       unsigned char **out, size_t *out_len) {
  unsigned char sk[32], our_pk[32];
  unsigned char *full = NULL;
  size_t full_len, id_len = sizeof(sk);
  const unsigned char *p, *end;
  char arg_b64[128], body_b64[128];
  size_t arg_len = 0, body_b64_len = 0, body_len = 64;
  unsigned char eph_pk[32], body[64];
  unsigned char shared[32], salt[64], wrap_key[32], file_key[AGE_FILE_KEY_LEN];
  unsigned char stream_nonce[AGE_STREAM_NONCE_LEN], stream_key[32];
  unsigned char zero_nonce[SLIVER_CHACHAPOLY_NONCE_LEN] = {0};
  size_t payload_len, chunks;
  unsigned char *plain = NULL;
  int rc = -1;
  
  if (identity == NULL || ciphertext == NULL || out == NULL || out_len == NULL) {
    return -1;
  }
  if (sliver_bech32_decode(identity, sk, &id_len) != 0 || id_len != 32) {
    return -1;
  }
  if (x25519_public_from_secret(sk, our_pk) != 0) {
    goto cleanup;
  }

  full_len = AGE_PREFIX_LEN + ciphertext_len;
  full = (unsigned char *)malloc(full_len);
  if (full == NULL) {
    goto cleanup;
  }
  memcpy(full, AGE_STANZA_PREFIX, AGE_PREFIX_LEN);
  memcpy(full + AGE_PREFIX_LEN, ciphertext, ciphertext_len);

  p = full + AGE_PREFIX_LEN;
  end = full + full_len;

  { /* arg line */
    const unsigned char *nl = (const unsigned char *)memchr(p, '\n', (size_t)(end - p));
    if (nl == NULL || (size_t)(nl - p) >= sizeof(arg_b64)) {
      goto cleanup;
    }
    arg_len = (size_t)(nl - p);
    memcpy(arg_b64, p, arg_len);
    arg_b64[arg_len] = '\0';
    p = nl + 1;
  }
  { /* body line(s) until the "---" footer */
    const unsigned char *nl = (const unsigned char *)memchr(p, '\n', (size_t)(end - p));
    if (nl == NULL || (size_t)(nl - p) >= sizeof(body_b64)) {
      goto cleanup;
    }
    body_b64_len = (size_t)(nl - p);
    memcpy(body_b64, p, body_b64_len);
    body_b64[body_b64_len] = '\0';
    p = nl + 1;
  }

  if (b64_raw_decode(arg_b64, arg_len, eph_pk, &(size_t){32}) != 0) {
    goto cleanup;
  }
  if (b64_raw_decode(body_b64, body_b64_len, body, &body_len) != 0 ||
      body_len != AGE_FILE_KEY_LEN + SLIVER_CHACHAPOLY_TAG_LEN) {
    goto cleanup;
  }
  { /* footer line: "--- <mac>" (the MAC itself is verified by the server path) */
    const unsigned char *nl = (const unsigned char *)memchr(p, '\n', (size_t)(end - p));
    if (nl == NULL || (size_t)(nl - p) < 3 || memcmp(p, "---", 3) != 0) {
      goto cleanup;
    }
    p = nl + 1;
  }
  if (sliver_x25519_shared(sk, eph_pk, shared) != 0) {
    goto cleanup;
  }
  memcpy(salt, eph_pk, 32);
  memcpy(salt + 32, our_pk, 32);
  if (sliver_hkdf_sha256(shared, 32, salt, sizeof(salt), AGE_LABEL, strlen(AGE_LABEL),
                         wrap_key, sizeof(wrap_key)) != 0) {
    goto cleanup;
  }
  if (sliver_chachapoly_open(wrap_key, zero_nonce, NULL, 0, body, body_len, file_key) != 0) {
    goto cleanup;
  }

  if ((size_t)(end - p) < AGE_STREAM_NONCE_LEN + SLIVER_CHACHAPOLY_TAG_LEN) {
    goto cleanup;
  }
  memcpy(stream_nonce, p, AGE_STREAM_NONCE_LEN);
  p += AGE_STREAM_NONCE_LEN;
  payload_len = (size_t)(end - p);
  chunks = (payload_len + (AGE_CHUNK_SIZE + SLIVER_CHACHAPOLY_TAG_LEN) - 1) /
           (AGE_CHUNK_SIZE + SLIVER_CHACHAPOLY_TAG_LEN);
  if (chunks == 0) {
    chunks = 1;
  }
  plain = (unsigned char *)malloc(payload_len);
  if (plain == NULL) {
    goto cleanup;
  }
  if (sliver_hkdf_sha256(file_key, sizeof(file_key), stream_nonce, sizeof(stream_nonce),
                         "payload", 7, stream_key, sizeof(stream_key)) != 0) {
    goto cleanup;
  }
  {
    size_t consumed = 0, written = 0;
    for (size_t i = 0; i < chunks; ++i) {
      unsigned char nonce[SLIVER_CHACHAPOLY_NONCE_LEN];
      size_t remaining = payload_len - consumed;
      size_t chunk_enc = remaining > (AGE_CHUNK_SIZE + SLIVER_CHACHAPOLY_TAG_LEN)
                             ? (AGE_CHUNK_SIZE + SLIVER_CHACHAPOLY_TAG_LEN)
                             : remaining;
      stream_nonce_for(nonce, i, i == chunks - 1);
      if (sliver_chachapoly_open(stream_key, nonce, NULL, 0, p + consumed, chunk_enc,
                                 plain + written) != 0) {
        goto cleanup;
      }
      written += chunk_enc - SLIVER_CHACHAPOLY_TAG_LEN;
      consumed += chunk_enc;
    }
    *out = plain;
    *out_len = written;
    plain = NULL;
  }
  rc = 0;

cleanup:
  free(full);
  free(plain);
  sliver_secure_zero(sk, sizeof(sk));
  sliver_secure_zero(shared, sizeof(shared));
  sliver_secure_zero(wrap_key, sizeof(wrap_key));
  sliver_secure_zero(file_key, sizeof(file_key));
  sliver_secure_zero(stream_key, sizeof(stream_key));
  return rc;
}


