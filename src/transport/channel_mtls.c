/* src/transport/channel_mtls.c - STREAM channel over mTLS + "MUX/1" + yamux.
 *
 * This is the pipeline that used to live inline in modes/session.c: TLS 1.3
 * mutual auth, the Sliver preface, hashicorp/yamux and the Ed25519-signed
 * envelope frame. Everything here is private to the channel layer.
 */
#include "sliver/channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/transport.h"
#include "sliver/yamux.h"

typedef struct {
  sliver_transport_t *transport;
  sliver_yamux_t yamux;
  sliver_frame_signer_t signer;
  const char *server_pubkey;
  char info[160];
  sliver_mutex_t *send_lock;
  volatile int closed;
} mtls_channel_t;

typedef struct {
  sliver_yamux_t *y;
  uint32_t stream_id;
  int failed;
} mtls_stream_t;

static long stream_read(void *ctx, void *buf, size_t len) {
  mtls_stream_t *s = (mtls_stream_t *)ctx;
  long n = sliver_yamux_read(s->y, s->stream_id, buf, len);
  if (n < 0) {
    s->failed = 1;
  }
  return n;
}

static long stream_write(void *ctx, const void *buf, size_t len) {
  mtls_stream_t *s = (mtls_stream_t *)ctx;
  if (sliver_yamux_write(s->y, s->stream_id, buf, len) != 0) {
    s->failed = 1;
    return -1;
  }
  return (long)len;
}

static long transport_read(void *ctx, void *buf, size_t len) {
  sliver_transport_t *t = (sliver_transport_t *)ctx;
  return t->read(t, buf, len);
}

static long transport_write(void *ctx, const void *buf, size_t len) {
  sliver_transport_t *t = (sliver_transport_t *)ctx;
  return t->write(t, buf, len);
}

static const char *mtls_describe(sliver_channel_t *c) {
  mtls_channel_t *m = (mtls_channel_t *)c->state;
  return m->info;
}

static int mtls_send(sliver_channel_t *c, const void *envelope, size_t len) {
  mtls_channel_t *m = (mtls_channel_t *)c->state;
  mtls_stream_t stream;
  uint32_t sid = 0;
  int rc;

  if (m->send_lock != NULL) {
    sliver_mutex_lock(m->send_lock);
  }
  if (m->closed) {
    if (m->send_lock != NULL) {
      sliver_mutex_unlock(m->send_lock);
    }
    return -1;
  }
  if (sliver_yamux_open(&m->yamux, &sid) != 0) {
    if (!m->yamux.failed) {
      LOG_ERROR("mtls: yamux open failed");
    }
    if (m->send_lock != NULL) {
      sliver_mutex_unlock(m->send_lock);
    }
    return -1;
  }
  stream.y = &m->yamux;
  stream.stream_id = sid;
  stream.failed = 0;
  rc = sliver_frame_write(&m->signer, stream_write, &stream, envelope, len);
  if (rc != 0) {
    LOG_ERROR("mtls: frame write failed (stream %u, %u bytes)", sid, (unsigned)len);
  } else {
    LOG_DEBUG("mtls: sent envelope on stream %u (%u bytes)", sid, (unsigned)len);
  }
  (void)sliver_yamux_close_write(&m->yamux, sid);
  if (m->send_lock != NULL) {
    sliver_mutex_unlock(m->send_lock);
  }
  return rc;
}

static int mtls_recv(sliver_channel_t *c, sliver_buf_t *env_out) {
  mtls_channel_t *m = (mtls_channel_t *)c->state;
  mtls_stream_t stream;
  uint32_t sid = 0;
  int rc;

  if (m->closed) {
    return 1;
  }
  if (sliver_yamux_accept(&m->yamux, &sid) != 0) {
    return 1; /* the link is gone: the scheduler must reconnect */
  }
  stream.y = &m->yamux;
  stream.stream_id = sid;
  stream.failed = 0;

  rc = sliver_frame_read(m->server_pubkey, stream_read, &stream, env_out);
  (void)sliver_yamux_close_write(&m->yamux, sid);
  if (rc != 0) {
    LOG_WARN("mtls: bad frame on stream %u", sid);
    return -1;
  }
  return 0;
}

static void mtls_close(sliver_channel_t *c) {
  mtls_channel_t *m = (mtls_channel_t *)c->state;
  if (m == NULL || m->closed) {
    return;
  }
  m->closed = 1;
  sliver_yamux_free(&m->yamux);
  if (m->transport != NULL) {
    sliver_transport_free(m->transport);
    m->transport = NULL;
  }
}

int sliver_channel_mtls_dial(const char *host, uint16_t port, const char *ca_pem,
                             const char *cert_pem, const char *key_pem,
                             const char *age_private_key,
                             const char *server_minisign_pubkey, sliver_channel_t **out,
                             char *err, size_t err_len) {
  sliver_channel_t *c;
  mtls_channel_t *m;

  if (out == NULL) {
    return -1;
  }
  *out = NULL;
  if (host == NULL || ca_pem == NULL || cert_pem == NULL || key_pem == NULL ||
      age_private_key == NULL || server_minisign_pubkey == NULL) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "mtls: missing channel arguments");
    }
    return -1;
  }

  c = (sliver_channel_t *)calloc(1, sizeof(*c));
  m = (mtls_channel_t *)calloc(1, sizeof(*m));
  if (c == NULL || m == NULL) {
    free(c);
    free(m);
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "mtls: out of memory");
    }
    return -1;
  }

  /* Signer first, matching the previous inline order (a failure here must not
   * leave a connected transport behind). */
  if (sliver_frame_signer_init(&m->signer, age_private_key) != 0) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "cannot derive envelope signing key");
    }
    free(m);
    free(c);
    return -1;
  }
  m->server_pubkey = server_minisign_pubkey;

  if (sliver_transport_connect(&m->transport, host, port, ca_pem, cert_pem, key_pem, err,
                               err_len) != 0) {
    free(m);
    free(c);
    return -1;
  }
  (void)snprintf(m->info, sizeof(m->info), "%s / %s", m->transport->version(m->transport),
                 m->transport->ciphersuite(m->transport));

  if (m->transport->write(m->transport, SLIVER_YAMUX_PREFACE, SLIVER_YAMUX_PREFACE_LEN) !=
      SLIVER_YAMUX_PREFACE_LEN) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "MUX/1 write failed");
    }
    sliver_transport_free(m->transport);
    free(m);
    free(c);
    return -1;
  }
  if (sliver_yamux_client(&m->yamux, transport_read, transport_write, m->transport) != 0) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "yamux client failed");
    }
    sliver_transport_free(m->transport);
    free(m);
    free(c);
    return -1;
  }
  m->send_lock = sliver_mutex_create();

  c->kind = SLIVER_CHANNEL_STREAM;
  c->describe = mtls_describe;
  c->send = mtls_send;
  c->recv = mtls_recv;
  c->poll = NULL;
  c->close = mtls_close;
  c->state = m;

  *out = c;
  return 0;
}

void sliver_channel_free(sliver_channel_t *c) {
  mtls_channel_t *m;
  if (c == NULL) {
    return;
  }
  m = (mtls_channel_t *)c->state;
  if (c->close != NULL) {
    c->close(c);
  }
  /* send_lock is intentionally not destroyed: detached workers (shell reader,
   * portfwd relay, execute/file) may still be inside send() holding it. One
   * leaked mutex per process is the safe trade (same reasoning as the previous
   * session-level tx_lock). */
  free(m);
  free(c);
}
