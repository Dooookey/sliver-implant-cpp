/* src/crypto/minisign.c - minisign raw signature verification.
 *
 * Sliver prefixes every server->implant envelope (mTLS/WG transports and the
 * HTTP/DNS ciphertext) with a 74 byte minisign signature:
 *
 *   [0:2]   u16 LE algorithm   (0x6445 EdDSA, 0x4445 HashEdDSA)
 *   [2:10]  u64 LE key id      (LE64(BLAKE2b-256(public key)[:8]))
 *   [10:74] ed25519 signature over the message (or over BLAKE2b-512(message))
 *
 * The public key is injected as the two line minisign public key file:
 *   untrusted comment: minisign public key: <ID hex>
 *   <base64(42 bytes: algo | key id | public key)>
 */
#include "sliver/crypto.h"

#include <string.h>

#define MINISIGN_ALG_EDDSA 0x6445u
#define MINISIGN_ALG_HASHEDDSA 0x4445u

static int b64_decode_std(const char *in, size_t in_len, unsigned char *out, size_t *out_len) {
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0;
  for (size_t i = 0; i < in_len; ++i) {
    char c = in[i];
    const char *p;
    int v;
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
      continue;
    }
    if (c == '=') {
      break;
    }
    p = strchr(tbl, c);
    if (p == NULL) {
      return -1;
    }
    v = (int)(p - tbl);
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

static uint64_t load_u64_le(const unsigned char *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i) {
    v = (v << 8) | p[i];
  }
  return v;
}

int sliver_minisign_keyid(const unsigned char public_key[32], uint64_t *key_id) {
  unsigned char digest[32];
  if (public_key == NULL || key_id == NULL) {
    return -1;
  }
  if (sliver_blake2b(public_key, 32, digest, sizeof(digest)) != 0) {
    return -1;
  }
  *key_id = load_u64_le(digest);
  return 0;
}

/* Returns the raw 32 byte public key from the two line minisign public key text. */
static int parse_public_key(const char *pubkey_text, unsigned char public_key[32], uint64_t *key_id) {
  const char *nl;
  const char *line;
  unsigned char raw[64];
  size_t raw_len = sizeof(raw);
  size_t line_len;

  if (pubkey_text == NULL || public_key == NULL) {
    return -1;
  }
  nl = strchr(pubkey_text, '\n');
  if (nl == NULL) {
    return -1;
  }
  line = nl + 1;
  nl = strchr(line, '\n');
  line_len = nl == NULL ? strlen(line) : (size_t)(nl - line);
  if (line_len == 0) {
    return -1;
  }
  if (b64_decode_std(line, line_len, raw, &raw_len) != 0 || raw_len < 42) {
    return -1;
  }
  if (key_id != NULL) {
    *key_id = load_u64_le(raw + 2);
  }
  memcpy(public_key, raw + 10, 32);
  return 0;
}

int sliver_minisign_raw_verify(const char *pubkey_text,
                               const unsigned char raw_sig[SLIVER_MINISIGN_RAW_SIG_LEN],
                               const void *msg, size_t msg_len) {
  unsigned char public_key[32];
  unsigned char digest[64];
  uint64_t pub_key_id = 0, sig_key_id;
  uint16_t algorithm;
  const void *signed_msg = msg;
  size_t signed_len = msg_len;

  if (raw_sig == NULL || (msg == NULL && msg_len != 0)) {
    return -1;
  }
  if (parse_public_key(pubkey_text, public_key, &pub_key_id) != 0) {
    return -1;
  }
  algorithm = (uint16_t)(raw_sig[0] | ((uint16_t)raw_sig[1] << 8));
  sig_key_id = load_u64_le(raw_sig + 2);
  if (sig_key_id != pub_key_id) {
    return -1;
  }
  switch (algorithm) {
    case MINISIGN_ALG_EDDSA:
      break;
    case MINISIGN_ALG_HASHEDDSA:
      if (sliver_blake2b(msg, msg_len, digest, sizeof(digest)) != 0) {
        return -1;
      }
      signed_msg = digest;
      signed_len = sizeof(digest);
      break;
    default:
      return -1;
  }
  return sliver_ed25519_verify(public_key, signed_msg, signed_len, raw_sig + 10);
}
