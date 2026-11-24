/* src/proto/domain_enc.c - domain-specific protobuf encoders (fs/proc/net/privs/
 * services/registry). Kept separate from proto.c so the core protocol layer does
 * not include platform-domain headers. */
#include "sliver/fs.h"
#include "sliver/privs.h"
#include "sliver/registry.h"
#include "sliver/services.h"
#include "sliver/proc.h"
#include "sliver/proto.h"

#include <stdlib.h>
#include <string.h>

/* Shared with proto.c (each translation unit owns a copy): encodes a commonpb
 * Response into field 9. */
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

int sliver_ifconfig_encode(sliver_buf_t *out, const sliver_iface_t *ifs, int count, const char *err) {
  int i;

  if (out == NULL) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    sliver_buf_t msg;
    const sliver_iface_t *it = &ifs[i];
    int j;

    sliver_buf_init(&msg);
    if (sliver_buf_put_int32(&msg, 1, it->index) != 0 ||
        sliver_buf_put_string(&msg, 2, it->name) != 0 || sliver_buf_put_string(&msg, 3, it->mac) != 0) {
      sliver_buf_free(&msg);
      return -1;
    }
    for (j = 0; j < it->ip_count; ++j) {
      if (sliver_buf_put_string(&msg, 4, it->ips[j]) != 0) {
        sliver_buf_free(&msg);
        return -1;
      }
    }
    if (sliver_buf_put_tag(out, 1, 2) != 0 || sliver_buf_put_varint(out, msg.len) != 0 ||
        sliver_buf_append(out, msg.data, msg.len) != 0) {
      sliver_buf_free(&msg);
      return -1;
    }
    sliver_buf_free(&msg);
  }
  return encode_response(out, err);
}

static int encode_sockaddr(sliver_buf_t *out, uint32_t field, const char *ip, uint32_t port) {
  sliver_buf_t msg;

  sliver_buf_init(&msg);
  if (sliver_buf_put_string(&msg, 1, ip != NULL ? ip : "") != 0 ||
      sliver_buf_put_uint32(&msg, 2, port) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  if (sliver_buf_put_tag(out, field, 2) != 0 || sliver_buf_put_varint(out, msg.len) != 0 ||
      sliver_buf_append(out, msg.data, msg.len) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  sliver_buf_free(&msg);
  return 0;
}

int sliver_netstat_encode(sliver_buf_t *out, const sliver_sock_t *entries, int count,
                          const char *err) {
  int i;

  if (out == NULL) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    const sliver_sock_t *e = &entries[i];
    sliver_buf_t entry;
    sliver_buf_t proc;

    sliver_buf_init(&entry);
    if (encode_sockaddr(&entry, 1, e->local_ip, e->local_port) != 0 ||
        encode_sockaddr(&entry, 2, e->remote_ip, e->remote_port) != 0 ||
        sliver_buf_put_string(&entry, 3, e->state) != 0 ||
        sliver_buf_put_uint32(&entry, 4, e->uid) != 0 ||
        sliver_buf_put_string(&entry, 6, e->proto) != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    /* Process{Pid=1, Executable=3}. */
    if (e->pid > 0) {
      sliver_buf_init(&proc);
      if (sliver_buf_put_int32(&proc, 1, e->pid) != 0 ||
          (e->exe[0] != '\0' && sliver_buf_put_string(&proc, 3, e->exe) != 0)) {
        sliver_buf_free(&proc);
        sliver_buf_free(&entry);
        return -1;
      }
      if (sliver_buf_put_tag(&entry, 5, 2) != 0 || sliver_buf_put_varint(&entry, proc.len) != 0 ||
          sliver_buf_append(&entry, proc.data, proc.len) != 0) {
        sliver_buf_free(&proc);
        sliver_buf_free(&entry);
        return -1;
      }
      sliver_buf_free(&proc);
    }
    if (sliver_buf_put_tag(out, 1, 2) != 0 || sliver_buf_put_varint(out, entry.len) != 0 ||
        sliver_buf_append(out, entry.data, entry.len) != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    sliver_buf_free(&entry);
  }
  return encode_response(out, err);
}

int sliver_mount_encode(sliver_buf_t *out, const sliver_mount_t *mounts, int count,
                        const char *err) {
  int i;

  if (out == NULL) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    const sliver_mount_t *m = &mounts[i];
    sliver_buf_t msg;

    sliver_buf_init(&msg);
    if (sliver_buf_put_string(&msg, 1, m->volume_name) != 0 ||
        sliver_buf_put_string(&msg, 2, m->volume_type) != 0 ||
        sliver_buf_put_string(&msg, 3, m->mount_point) != 0 ||
        sliver_buf_put_string(&msg, 4, m->label) != 0 ||
        sliver_buf_put_string(&msg, 5, m->file_system) != 0 ||
        sliver_buf_put_uint64(&msg, 6, m->used_space) != 0 ||
        sliver_buf_put_uint64(&msg, 7, m->free_space) != 0 ||
        sliver_buf_put_uint64(&msg, 8, m->total_space) != 0) {
      sliver_buf_free(&msg);
      return -1;
    }
    if (sliver_buf_put_tag(out, 1, 2) != 0 || sliver_buf_put_varint(out, msg.len) != 0 ||
        sliver_buf_append(out, msg.data, msg.len) != 0) {
      sliver_buf_free(&msg);
      return -1;
    }
    sliver_buf_free(&msg);
  }
  return encode_response(out, err);
}

int sliver_reg_req_decode(const void *data, size_t len, sliver_reg_req_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  int rc;

  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  sliver_reader_init(&r, data, len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (wire == 2 && field == 1) {
      if (sliver_reader_string(&r, out->hive, sizeof(out->hive)) != 0) return -1;
    } else if (wire == 2 && field == 2) {
      if (sliver_reader_string(&r, out->path, sizeof(out->path)) != 0) return -1;
    } else if (wire == 2 && field == 3) {
      if (sliver_reader_string(&r, out->key, sizeof(out->key)) != 0) return -1;
    } else if (wire == 2 && field == 4) {
      if (sliver_reader_string(&r, out->hostname, sizeof(out->hostname)) != 0) return -1;
    } else if (wire == 2 && field == 5) {
      if (sliver_reader_string(&r, out->string_value, sizeof(out->string_value)) != 0) return -1;
    } else if (wire == 2 && field == 6) {
      const uint8_t *bytes;
      size_t n;
      if (sliver_reader_bytes(&r, &bytes, &n) != 0) return -1;
      if (n > sizeof(out->byte_value)) return -1;
      memcpy(out->byte_value, bytes, n);
      out->byte_len = n;
    } else if (wire == 0 && field == 7) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) return -1;
      out->dword = (uint32_t)v;
    } else if (wire == 0 && field == 8) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) return -1;
      out->qword = v;
    } else if (wire == 0 && field == 10) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) return -1;
      out->type = (uint32_t)v;
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  return rc == 1 ? 0 : -1;
}

int sliver_getprivs_encode(sliver_buf_t *out, const sliver_priv_t *privs, int count,
                           const char *integrity, const char *process_name, const char *err) {
  int i;

  if (out == NULL) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    sliver_buf_t entry;

    sliver_buf_init(&entry);
    if (sliver_buf_put_string(&entry, 1, privs[i].name) != 0 ||
        sliver_buf_put_string(&entry, 2, privs[i].description) != 0 ||
        (privs[i].enabled && sliver_buf_put_bool(&entry, 3, 1) != 0) ||
        (privs[i].enabled_by_default && sliver_buf_put_bool(&entry, 4, 1) != 0) ||
        (privs[i].removed && sliver_buf_put_bool(&entry, 5, 1) != 0)) {
      sliver_buf_free(&entry);
      return -1;
    }
    if (sliver_buf_put_tag(out, 1, 2) != 0 || sliver_buf_put_varint(out, entry.len) != 0 ||
        sliver_buf_append(out, entry.data, entry.len) != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    sliver_buf_free(&entry);
  }
  if (integrity != NULL && integrity[0] != 0 && sliver_buf_put_string(out, 2, integrity) != 0) {
    return -1;
  }
  if (process_name != NULL && process_name[0] != 0 &&
      sliver_buf_put_string(out, 3, process_name) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

int sliver_execute_children_encode(sliver_buf_t *out, const sliver_child_proc_t *children,
                                   int count, const char *err) {
  int i;

  if (out == NULL) {
    return -1;
  }
  for (i = 0; i < count; ++i) {
    sliver_buf_t msg;

    sliver_buf_init(&msg);
    if (sliver_buf_put_int32(&msg, 1, children[i].pid) != 0 ||
        sliver_buf_put_string(&msg, 2, children[i].path) != 0) {
      sliver_buf_free(&msg);
      return -1;
    }
    if (sliver_buf_put_tag(out, 1, 2) != 0 || sliver_buf_put_varint(out, msg.len) != 0 ||
        sliver_buf_append(out, msg.data, msg.len) != 0) {
      sliver_buf_free(&msg);
      return -1;
    }
    sliver_buf_free(&msg);
  }
  return encode_response(out, err);
}

static int encode_service(sliver_buf_t *entry, const sliver_service_t *svc) {
  if (sliver_buf_put_string(entry, 1, svc->name) != 0 ||
      sliver_buf_put_string(entry, 2, svc->display_name) != 0 ||
      sliver_buf_put_string(entry, 3, svc->description) != 0 ||
      sliver_buf_put_uint32(entry, 4, svc->status) != 0 ||
      sliver_buf_put_uint32(entry, 5, svc->startup_type) != 0 ||
      sliver_buf_put_string(entry, 6, svc->bin_path) != 0 ||
      sliver_buf_put_string(entry, 7, svc->account) != 0) {
    return -1;
  }
  return 0;
}

int sliver_services_encode(sliver_buf_t *out, const sliver_service_t *svcs, int count,
                           const char *err) {
  int i;

  for (i = 0; i < count; ++i) {
    sliver_buf_t entry;
    sliver_buf_init(&entry);
    if (encode_service(&entry, &svcs[i]) != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    if (sliver_buf_put_tag(out, 1, 2) != 0 || sliver_buf_put_varint(out, entry.len) != 0 ||
        sliver_buf_append(out, entry.data, entry.len) != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    sliver_buf_free(&entry);
  }
  if (err != NULL && err[0] != 0 && sliver_buf_put_string(out, 2, err) != 0) {
    return -1;
  }
  return encode_response(out, err);
}

int sliver_service_detail_encode(sliver_buf_t *out, const sliver_service_t *svc, const char *msg,
                                 const char *err) {
  if (svc != NULL) {
    sliver_buf_t entry;
    sliver_buf_init(&entry);
    if (encode_service(&entry, svc) != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    if (sliver_buf_put_tag(out, 1, 2) != 0 || sliver_buf_put_varint(out, entry.len) != 0 ||
        sliver_buf_append(out, entry.data, entry.len) != 0) {
      sliver_buf_free(&entry);
      return -1;
    }
    sliver_buf_free(&entry);
  }
  if (msg != NULL && msg[0] != 0 && sliver_buf_put_string(out, 2, msg) != 0) {
    return -1;
  }
  return encode_response(out, err);
}
