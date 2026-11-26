/* src/crypto/gzip.c - minimal gzip for the HTTP C2 payload layer.
 *
 * Sliver's CipherContext always runs the plaintext through gzip before
 * encrypting and after decrypting (implant/sliver/cryptography/crypto.go
 * gzipBuf/gunzipBuf), so both directions are required:
 *
 *   compress   : a valid gzip stream. Compression level is irrelevant for
 *                correctness, so this emits stored (type 0) blocks, which keeps
 *                the encoder tiny and still decodes with any gzip reader.
 *   decompress : a real DEFLATE decoder (stored, fixed and dynamic Huffman)
 *                because the Go side compresses with gzip.BestSpeed.
 *
 * The decoder is a puff-style bit-by-bit canonical Huffman walk: slower than a
 * table-driven inflate but small, allocation-light and easy to verify against
 * Go-generated fixtures.
 */
#include "sliver/crypto.h"

#include <stdlib.h>
#include <string.h>

/* --- CRC32 (gzip trailer) ------------------------------------------------ */
static uint32_t gzip_crc32(const unsigned char *data, size_t len) {
  static uint32_t table[256];
  static int ready = 0;
  uint32_t crc = 0xFFFFFFFFu;
  size_t i;

  if (!ready) {
    uint32_t n;
    for (n = 0; n < 256; ++n) {
      uint32_t c = n;
      int k;
      for (k = 0; k < 8; ++k) {
        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      }
      table[n] = c;
    }
    ready = 1;
  }
  for (i = 0; i < len; ++i) {
    crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

/* --- growable output buffer --------------------------------------------- */
typedef struct {
  unsigned char *data;
  size_t len;
  size_t cap;
  int failed;
} obuf_t;

static int obuf_reserve(obuf_t *o, size_t extra) {
  if (o->failed) {
    return -1;
  }
  if (o->len + extra > o->cap) {
    size_t want = o->cap == 0 ? 4096 : o->cap;
    unsigned char *grown;
    while (want < o->len + extra) {
      want *= 2;
    }
    grown = (unsigned char *)realloc(o->data, want);
    if (grown == NULL) {
      o->failed = 1;
      return -1;
    }
    o->data = grown;
    o->cap = want;
  }
  return 0;
}

static int obuf_put(obuf_t *o, const void *src, size_t n) {
  if (obuf_reserve(o, n) != 0) {
    return -1;
  }
  memcpy(o->data + o->len, src, n);
  o->len += n;
  return 0;
}

static int obuf_put_byte(obuf_t *o, unsigned char b) {
  if (obuf_reserve(o, 1) != 0) {
    return -1;
  }
  o->data[o->len++] = b;
  return 0;
}

/* --- compress (stored blocks) ------------------------------------------- */
int sliver_gzip_compress(const void *data, size_t len, unsigned char **out,
                         size_t *out_len) {
  static const unsigned char header[10] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0xff};
  obuf_t o;
  const unsigned char *src = (const unsigned char *)data;
  uint32_t crc;
  unsigned char trailer[8];
  size_t offset = 0;

  if (out == NULL || out_len == NULL || (data == NULL && len != 0)) {
    return -1;
  }
  memset(&o, 0, sizeof(o));
  if (obuf_put(&o, header, sizeof(header)) != 0) {
    free(o.data);
    return -1;
  }
  do {
    size_t chunk = len - offset;
    unsigned char block_head[5];
    int last;
    if (chunk > 65535u) {
      chunk = 65535u;
    }
    last = (offset + chunk == len) ? 1 : 0;
    /* Stored block: BFINAL/BTYPE=00, then align, LEN, NLEN, raw bytes. The bit
     * pattern 0x00 already leaves the stream byte aligned. */
    block_head[0] = (unsigned char)(last ? 0x01 : 0x00);
    block_head[1] = (unsigned char)(chunk & 0xFFu);
    block_head[2] = (unsigned char)((chunk >> 8) & 0xFFu);
    block_head[3] = (unsigned char)(~chunk & 0xFFu);
    block_head[4] = (unsigned char)((~chunk >> 8) & 0xFFu);
    if (obuf_put(&o, block_head, sizeof(block_head)) != 0 ||
        (chunk != 0 && obuf_put(&o, src + offset, chunk) != 0)) {
      free(o.data);
      return -1;
    }
    offset += chunk;
  } while (offset < len);

  crc = gzip_crc32(src, len);
  trailer[0] = (unsigned char)(crc & 0xFFu);
  trailer[1] = (unsigned char)((crc >> 8) & 0xFFu);
  trailer[2] = (unsigned char)((crc >> 16) & 0xFFu);
  trailer[3] = (unsigned char)((crc >> 24) & 0xFFu);
  trailer[4] = (unsigned char)(len & 0xFFu);
  trailer[5] = (unsigned char)((len >> 8) & 0xFFu);
  trailer[6] = (unsigned char)((len >> 16) & 0xFFu);
  trailer[7] = (unsigned char)((len >> 24) & 0xFFu);
  if (obuf_put(&o, trailer, sizeof(trailer)) != 0) {
    free(o.data);
    return -1;
  }

  *out = o.data;
  *out_len = o.len;
  return 0;
}

/* --- decompress (DEFLATE) ------------------------------------------------ */
typedef struct {
  const unsigned char *data;
  size_t len;
  size_t pos;   /* byte position */
  unsigned bit; /* bit position inside data[pos] (LSB first) */
  int failed;
} bitreader_t;

static int bits(bitreader_t *br, int need) {
  int value = 0;
  int got = 0;
  while (got < need) {
    unsigned char byte;
    if (br->pos >= br->len) {
      br->failed = 1;
      return 0;
    }
    byte = br->data[br->pos];
    value |= ((byte >> br->bit) & 1u) << got;
    got++;
    br->bit++;
    if (br->bit == 8) {
      br->bit = 0;
      br->pos++;
    }
  }
  return value;
}

typedef struct {
  short count[16];  /* number of codes per length */
  short symbol[288]; /* symbols ordered by code */
} huffman_t;

static int huffman_build(huffman_t *h, const short *lengths, int n) {
  short offs[16];
  int i;
  int left = 1;

  for (i = 0; i < 16; ++i) {
    h->count[i] = 0;
  }
  for (i = 0; i < n; ++i) {
    h->count[lengths[i]]++;
  }
  if (h->count[0] == n) {
    return 0; /* no codes: legal, means "no symbols" */
  }
  for (i = 1; i < 16; ++i) {
    left <<= 1;
    left -= h->count[i];
    if (left < 0) {
      return -1; /* over-subscribed */
    }
  }
  offs[1] = 0;
  for (i = 1; i < 15; ++i) {
    offs[i + 1] = (short)(offs[i] + h->count[i]);
  }
  for (i = 0; i < n; ++i) {
    if (lengths[i] != 0) {
      h->symbol[offs[lengths[i]]++] = (short)i;
    }
  }
  return left;
}

static int huffman_decode(bitreader_t *br, const huffman_t *h) {
  int code = 0;
  int first = 0;
  int index = 0;
  int length;
  for (length = 1; length < 16; ++length) {
    int value;
    code |= bits(br, 1);
    if (br->failed) {
      return -1;
    }
    value = h->count[length];
    if (code - first < value) {
      return h->symbol[index + (code - first)];
    }
    index += value;
    first += value;
    first <<= 1;
    code <<= 1;
  }
  return -1;
}

static const short k_len_base[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,
                                     15, 17, 19, 23, 27, 31, 35, 43, 51,  59,
                                     67, 83, 99, 115, 131, 163, 195, 227, 258};
static const short k_len_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                      2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const short k_dist_base[30] = {1,    2,    3,    4,    5,    7,     9,     13,
                                      17,   25,   33,   49,   65,   97,    129,   193,
                                      257,  385,  513,  769,  1025, 1537,  2049,  3073,
                                      4097, 6145, 8193, 12289, 16385, 24577};
static const short k_dist_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                                       6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static int inflate_block(bitreader_t *br, obuf_t *out, const huffman_t *lit,
                         const huffman_t *dist) {
  for (;;) {
    int symbol = huffman_decode(br, lit);
    if (symbol < 0) {
      return -1;
    }
    if (symbol < 256) {
      if (obuf_put_byte(out, (unsigned char)symbol) != 0) {
        return -1;
      }
    } else if (symbol == 256) {
      return 0;
    } else {
      int len_index = symbol - 257;
      int length;
      int dist_symbol;
      int distance;
      if (len_index < 0 || len_index >= 29) {
        return -1;
      }
      length = k_len_base[len_index] + bits(br, k_len_extra[len_index]);
      dist_symbol = huffman_decode(br, dist);
      if (dist_symbol < 0 || dist_symbol >= 30) {
        return -1;
      }
      distance = k_dist_base[dist_symbol] + bits(br, k_dist_extra[dist_symbol]);
      if (br->failed || (size_t)distance > out->len) {
        return -1;
      }
      if (obuf_reserve(out, (size_t)length) != 0) {
        return -1;
      }
      {
        size_t from = out->len - (size_t)distance;
        int i;
        for (i = 0; i < length; ++i) {
          out->data[out->len++] = out->data[from + (size_t)i];
        }
      }
    }
  }
}

static int inflate_dynamic(bitreader_t *br, obuf_t *out) {
  static const short order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13,
                                  2, 14, 1, 15};
  short lengths[320];
  huffman_t lit;
  huffman_t dist;
  int nlen = bits(br, 5) + 257;
  int ndist = bits(br, 5) + 1;
  int ncode = bits(br, 4) + 4;
  int i;
  int index = 0;

  if (br->failed || nlen > 286 || ndist > 30) {
    return -1;
  }
  memset(lengths, 0, sizeof(lengths));
  for (i = 0; i < ncode; ++i) {
    lengths[order[i]] = (short)bits(br, 3);
  }
  if (br->failed || huffman_build(&lit, lengths, 19) != 0) {
    return -1;
  }
  memset(lengths, 0, sizeof(lengths));
  while (index < nlen + ndist) {
    int symbol = huffman_decode(br, &lit);
    int repeat;
    short value;
    if (symbol < 0) {
      return -1;
    }
    if (symbol < 16) {
      lengths[index++] = (short)symbol;
      continue;
    }
    if (symbol == 16) {
      if (index == 0) {
        return -1;
      }
      value = lengths[index - 1];
      repeat = 3 + bits(br, 2);
    } else if (symbol == 17) {
      value = 0;
      repeat = 3 + bits(br, 3);
    } else {
      value = 0;
      repeat = 11 + bits(br, 7);
    }
    if (br->failed || index + repeat > nlen + ndist) {
      return -1;
    }
    while (repeat-- > 0) {
      lengths[index++] = value;
    }
  }
  if (huffman_build(&lit, lengths, nlen) < 0) {
    return -1;
  }
  if (huffman_build(&dist, lengths + nlen, ndist) < 0) {
    return -1;
  }
  return inflate_block(br, out, &lit, &dist);
}

static int inflate_raw(const unsigned char *src, size_t len, obuf_t *out) {
  bitreader_t br;
  int last = 0;

  memset(&br, 0, sizeof(br));
  br.data = src;
  br.len = len;
  while (!last) {
    int type;
    last = bits(&br, 1);
    type = bits(&br, 2);
    if (br.failed) {
      return -1;
    }
    if (type == 0) {
      size_t stored_len;
      br.bit = 0;
      br.pos++; /* skip to the next byte boundary */
      if (br.pos + 4 > br.len) {
        return -1;
      }
      stored_len = (size_t)br.data[br.pos] | ((size_t)br.data[br.pos + 1] << 8);
      br.pos += 4;
      if (br.pos + stored_len > br.len || obuf_put(out, br.data + br.pos, stored_len) != 0) {
        return -1;
      }
      br.pos += stored_len;
    } else if (type == 1) {
      short lengths[288];
      huffman_t lit;
      huffman_t dist;
      int i;
      for (i = 0; i < 144; ++i) {
        lengths[i] = 8;
      }
      for (; i < 256; ++i) {
        lengths[i] = 9;
      }
      for (; i < 280; ++i) {
        lengths[i] = 7;
      }
      for (; i < 288; ++i) {
        lengths[i] = 8;
      }
      if (huffman_build(&lit, lengths, 288) < 0) {
        return -1;
      }
      for (i = 0; i < 30; ++i) {
        lengths[i] = 5;
      }
      if (huffman_build(&dist, lengths, 30) < 0) {
        return -1;
      }
      if (inflate_block(&br, out, &lit, &dist) != 0) {
        return -1;
      }
    } else if (type == 2) {
      if (inflate_dynamic(&br, out) != 0) {
        return -1;
      }
    } else {
      return -1;
    }
  }
  return 0;
}

int sliver_gzip_decompress(const void *data, size_t len, unsigned char **out,
                           size_t *out_len, size_t max_out) {
  const unsigned char *src = (const unsigned char *)data;
  obuf_t o;
  int flags;
  size_t pos = 10;

  if (out == NULL || out_len == NULL || src == NULL) {
    return -1;
  }
  if (len < 18 || src[0] != 0x1f || src[1] != 0x8b || src[2] != 0x08) {
    return -1;
  }
  flags = src[3];
  if (flags & 0x04) { /* FEXTRA */
    size_t xlen;
    if (pos + 2 > len) {
      return -1;
    }
    xlen = (size_t)src[pos] | ((size_t)src[pos + 1] << 8);
    pos += 2 + xlen;
  }
  if (flags & 0x08) { /* FNAME */
    while (pos < len && src[pos] != 0) {
      pos++;
    }
    pos++;
  }
  if (flags & 0x10) { /* FCOMMENT */
    while (pos < len && src[pos] != 0) {
      pos++;
    }
    pos++;
  }
  if (flags & 0x02) { /* FHCRC */
    pos += 2;
  }
  if (pos + 8 > len) {
    return -1;
  }

  memset(&o, 0, sizeof(o));
  if (inflate_raw(src + pos, len - pos - 8, &o) != 0) {
    free(o.data);
    return -1;
  }
  if (max_out != 0 && o.len > max_out) {
    free(o.data);
    return -1;
  }
  *out = o.data;
  *out_len = o.len;
  return 0;
}
