/* src/crypto/bech32.c - bech32 (BIP-173, not bech32m) for age key strings. */
#include "sliver/crypto.h"

#include <string.h>

static const char k_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static int charset_index(char c) {
  const char *p = strchr(k_charset, c);
  if (p == NULL) {
    return -1;
  }
  return (int)(p - k_charset);
}

static uint32_t bech32_polymod_step(uint32_t chk) {
  static const uint32_t gen[5] = {0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
  uint32_t top = chk >> 25;
  chk = ((chk & 0x1ffffffu) << 5) ^ (uint32_t)0;
  for (int i = 0; i < 5; ++i) {
    if ((top >> i) & 1u) {
      chk ^= gen[i];
    }
  }
  return chk;
}

static int convert_bits(const uint8_t *in, size_t in_len, int from_bits, int to_bits,
                        uint8_t *out, size_t *out_len, size_t out_cap, int pad) {
  uint32_t acc = 0;
  int bits = 0;
  size_t written = 0;
  const uint32_t max_v = (1u << to_bits) - 1u;

  for (size_t i = 0; i < in_len; ++i) {
    acc = (acc << from_bits) | in[i];
    bits += from_bits;
    while (bits >= to_bits) {
      bits -= to_bits;
      if (written >= out_cap) {
        return -1;
      }
      out[written++] = (uint8_t)((acc >> bits) & max_v);
    }
  }
  if (bits > 0) {
    if (!pad) {
      /* Decoding: leftover bits must be zero padding, and never produce a byte. */
      if ((acc & ((1u << bits) - 1u)) != 0) {
        return -1;
      }
    } else {
      if (written >= out_cap) {
        return -1;
      }
      out[written++] = (uint8_t)((acc << (to_bits - bits)) & max_v);
    }
  }
  *out_len = written;
  return 0;
}

int sliver_bech32_decode(const char *str, uint8_t *out, size_t *out_len) {
  size_t len, hrp_len, data_len;
  char hrp[84];
  char lower[128];
  uint8_t data[256];
  uint32_t chk = 1;
  size_t payload_len;

  if (str == NULL || out == NULL || out_len == NULL) {
    return -1;
  }
  len = strlen(str);
  if (len < 8 || len > 90 || len >= sizeof(lower)) {
    return -1;
  }
  /* bech32 is case-insensitive as long as it is uniform; age encodes secret
   * keys in upper case, so normalise before parsing. */
  for (size_t i = 0; i < len; ++i) {
    char c = str[i];
    lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
  }
  lower[len] = '\0';

  /* The separator is the last '1'. */
  for (hrp_len = len; hrp_len > 0; --hrp_len) {
    if (lower[hrp_len - 1] == '1') {
      break;
    }
  }
  if (hrp_len < 2) {
    return -1;
  }
  hrp_len -= 1; /* index of the separator */
  if (hrp_len >= sizeof(hrp)) {
    return -1;
  }
  for (size_t i = 0; i < hrp_len; ++i) {
    char c = lower[i];
    if (c < 33 || c > 126) {
      return -1;
    }
    hrp[i] = c;
  }
  hrp[hrp_len] = '\0';

  data_len = len - hrp_len - 1;
  if (data_len < 6 || data_len > sizeof(data)) {
    return -1;
  }
  for (size_t i = 0; i < data_len; ++i) {
    int idx = charset_index(lower[hrp_len + 1 + i]);
    if (idx < 0) {
      return -1;
    }
    data[i] = (uint8_t)idx;
  }

  /* BIP-173 checksum input: the HRP is expanded as its high bits, a zero
   * separator, then its low bits (bech32_hrp_expand). Feeding the raw ASCII
   * bytes instead only round-trips with a matching encoder, never with a real
   * age/GitHub style string. */
  for (size_t i = 0; i < hrp_len; ++i) {
    chk = bech32_polymod_step(chk) ^ (uint8_t)((uint8_t)hrp[i] >> 5);
  }
  chk = bech32_polymod_step(chk);
  for (size_t i = 0; i < hrp_len; ++i) {
    chk = bech32_polymod_step(chk) ^ (uint8_t)((uint8_t)hrp[i] & 31u);
  }
  for (size_t i = 0; i < data_len; ++i) {
    chk = bech32_polymod_step(chk) ^ data[i];
  }
  if (chk != 1) {
    return -1;
  }

  payload_len = data_len - 6;
  return convert_bits(data, payload_len, 5, 8, out, out_len, *out_len, 0);
}

int sliver_bech32_encode(const char *hrp, const uint8_t *data, size_t data_len,
                         char *out, size_t out_cap) {
  uint8_t data5[512];
  size_t data5_len = sizeof(data5);
  uint32_t chk = 1;
  size_t pos = 0;

  if (hrp == NULL || data == NULL || out == NULL) {
    return -1;
  }
  if (convert_bits(data, data_len, 8, 5, data5, &data5_len, sizeof(data5), 1) != 0) {
    return -1;
  }

  for (const char *p = hrp; *p; ++p) {
    if (pos + 1 >= out_cap) {
      return -1;
    }
    out[pos++] = *p;
  }
  if (pos + 1 + data5_len + 6 >= out_cap) {
    return -1;
  }
  out[pos++] = '1';

  for (size_t i = 0; i < data5_len; ++i) {
    out[pos++] = k_charset[data5[i]];
  }

  /* checksum (bech32 is case insensitive: always hash the lower case HRP, and
   * expand it as high bits + zero separator + low bits) */
  for (const char *p = hrp; *p; ++p) {
    char c = (*p >= 'A' && *p <= 'Z') ? (char)(*p - 'A' + 'a') : *p;
    chk = bech32_polymod_step(chk) ^ (uint8_t)((uint8_t)c >> 5);
  }
  chk = bech32_polymod_step(chk);
  for (const char *p = hrp; *p; ++p) {
    char c = (*p >= 'A' && *p <= 'Z') ? (char)(*p - 'A' + 'a') : *p;
    chk = bech32_polymod_step(chk) ^ (uint8_t)((uint8_t)c & 31u);
  }
  for (size_t i = 0; i < data5_len; ++i) {
    chk = bech32_polymod_step(chk) ^ data5[i];
  }
  for (int i = 0; i < 6; ++i) {
    chk = bech32_polymod_step(chk);
  }
  chk ^= 1u;
  for (int i = 0; i < 6; ++i) {
    out[pos++] = k_charset[(chk >> (5 * (5 - i))) & 31u];
  }
  out[pos] = '\0';
  return 0;
}

