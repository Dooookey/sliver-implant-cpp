/* src/rpc/dispatch.c - handler table and the first slice of Sliver RPCs. */
#include "sliver/rpc.h"

#include <stdlib.h>
#include <string.h>

#include "sliver/fs.h"
#include "sliver/log.h"

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
  return sliver_pwd_encode(out, cwd);
}

/* --- table ------------------------------------------------------------- */
static const rpc_entry_t g_handlers[] = {
    {SLIVER_MSG_LS_REQ, SLIVER_MSG_LS, sliver_rpc_handle_ls},
    {SLIVER_MSG_PWD_REQ, SLIVER_MSG_PWD, sliver_rpc_handle_pwd},
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
    if (g_handlers[i].fn(req, &result->message) == 0) {
      result->handled = 1;
      result->resp_type = g_handlers[i].resp_type;
    } else {
      /* Handler failed: answer with an empty response carrying the type so the
       * client sees a protocol error instead of a timeout. */
      sliver_buf_free(&result->message);
      sliver_buf_init(&result->message);
      result->handled = 1;
      result->resp_type = g_handlers[i].resp_type;
      LOG_ERROR("rpc: handler for type %u failed", req->type);
    }
    return;
  }
}
