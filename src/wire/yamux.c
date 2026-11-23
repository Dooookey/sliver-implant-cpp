/* src/wire/yamux.c - minimal client side of hashicorp/yamux. */
#include "sliver/yamux.h"

#include "sliver/log.h"
#include "sliver/platform.h"

#include <stdlib.h>
#include <string.h>

#define YAMUX_VERSION 0u
#define YAMUX_TYPE_DATA 0u
#define YAMUX_TYPE_WINDOW_UPDATE 1u
#define YAMUX_TYPE_PING 2u
#define YAMUX_TYPE_GO_AWAY 3u

#define YAMUX_FLAG_SYN 0x0001u
#define YAMUX_FLAG_ACK 0x0002u
#define YAMUX_FLAG_FIN 0x0004u
#define YAMUX_FLAG_RST 0x0008u

static void put_u16_be(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xff);
}

static void put_u32_be(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v & 0xff);
}

static uint16_t get_u16_be(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32_be(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

/* Fills y->hdr_buf up to 12 bytes, keeping the partial prefix across calls so a
 * receive timeout never splits a header. Returns 0 when a full header is
 * buffered, 1 when more data is needed, -1 on a fatal read error. */
static int io_fill_header(sliver_yamux_t *y) {
  while (y->hdr_got < sizeof(y->hdr_buf)) {
    long n = y->read_fn(y->ctx, y->hdr_buf + y->hdr_got, sizeof(y->hdr_buf) - y->hdr_got);
    if (n == -2) {
      /* No data yet (TLS receive timeout): the prefix read so far is kept. */
      return 1;
    }
    if (n <= 0) {
      return -1;
    }
    y->hdr_got += (size_t)n;
  }
  return 0;
}

/* Reads a frame body, which may arrive over several records. A timeout only
 * retries until the body deadline expires, so a slow peer does not tear down
 * the session while a stalled one still cannot hold it forever. */
static int io_read_body(sliver_yamux_t *y, void *buf, size_t len) {
  uint8_t *out = (uint8_t *)buf;
  size_t got = 0;
  uint64_t deadline = sliver_now_ms() + SLIVER_YAMUX_BODY_TIMEOUT_MS;

  while (got < len) {
    long n = y->read_fn(y->ctx, out + got, len - got);
    if (n == -2) {
      if (sliver_now_ms() >= deadline) {
        return -1;
      }
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    got += (size_t)n;
  }
  return 0;
}

static int io_write_full(sliver_yamux_t *y, const void *buf, size_t len) {
  size_t sent = 0;
  int retries = 0;

  while (sent < len) {
    long n = y->write_fn(y->ctx, (const uint8_t *)buf + sent, len - sent);
    if (n == -2) {
      /* Transient WANT_READ/WANT_WRITE: retry the same bytes. The 5 s bound matches
       * the socket send timeout; a peer that is momentarily not reading (or an
       * mbedTLS post-handshake read) clears within this window. */
      if (++retries > 5000) {
        return -1;
      }
      sliver_sleep_ms(1);
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    retries = 0;
    sent += (size_t)n;
  }
  return 0;
}

static int send_frame(sliver_yamux_t *y, uint8_t type, uint16_t flags, uint32_t stream_id,
                      const void *payload, uint32_t length) {
  uint8_t header[12];
  int rc;
  header[0] = YAMUX_VERSION;
  header[1] = type;
  put_u16_be(header + 2, flags);
  put_u32_be(header + 4, stream_id);
  put_u32_be(header + 8, length);
  /* open/write/close and the pump (ACK, window updates) run on different
   * threads: without this lock two frames interleave and the peer sees garbage. */
  if (y->write_lock != NULL) {
    sliver_mutex_lock(y->write_lock);
  }
  rc = io_write_full(y, header, sizeof(header));
  if (rc == 0 && length != 0 && payload != NULL) {
    rc = io_write_full(y, payload, length);
  }
  if (rc != 0) {
    LOG_ERROR("yamux: io_write_full failed (type %u, stream %u, len %u)", type, stream_id,
              length);
  }
  if (y->write_lock != NULL) {
    sliver_mutex_unlock(y->write_lock);
  }
  return rc;
}

static void release_stream(sliver_yamux_stream_t *s) {
  if (s == NULL || !s->used) {
    return;
  }
  sliver_buf_free(&s->in);
  memset(s, 0, sizeof(*s));
}

/* Frees the slot once both sides are done with the stream. */
static void maybe_release(sliver_yamux_stream_t *s) {
  if (s != NULL && s->used && s->fin_received && s->closed_write &&
      s->in_off >= s->in.len) {
    release_stream(s);
  }
}

static sliver_yamux_stream_t *find_stream(sliver_yamux_t *y, uint32_t id) {
  for (size_t i = 0; i < SLIVER_YAMUX_MAX_STREAMS; ++i) {
    if (y->streams[i].used && y->streams[i].id == id) {
      return &y->streams[i];
    }
  }
  return NULL;
}

/* True when `id` is a stream we opened ourselves (monotonic: never reused). A
 * SYN frame on such an id is the peer's ACK, not a new stream. */
static int is_local_id(const sliver_yamux_t *y, uint32_t id) {
  for (size_t i = 0; i < y->local_count; ++i) {
    if (y->local_ids[i] == id) {
      return 1;
    }
  }
  return 0;
}

static void pending_push(sliver_yamux_t *y, uint32_t id) {
  if (y->pending_count >= SLIVER_YAMUX_MAX_PENDING) {
    /* Backlog full: reset the stream instead of silently dropping the request
     * (Go closes the session when its own backlog overflows). */
    (void)send_frame(y, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_RST, id, NULL, 0);
    release_stream(find_stream(y, id));
    return;
  }
  y->pending_ids[(y->pending_head + y->pending_count) % SLIVER_YAMUX_MAX_PENDING] = id;
  y->pending_count++;
}

static int pending_pop(sliver_yamux_t *y, uint32_t *id) {
  if (y->pending_count == 0) {
    return 0;
  }
  *id = y->pending_ids[y->pending_head];
  y->pending_head = (y->pending_head + 1) % SLIVER_YAMUX_MAX_PENDING;
  y->pending_count--;
  return 1;
}

static sliver_yamux_stream_t *alloc_stream(sliver_yamux_t *y, uint32_t id) {
  sliver_yamux_stream_t *s = find_stream(y, id);
  if (s != NULL) {
    return s;
  }
  /* Table full: reclaim a stream that is finished on both directions. The peer
   * often never sends FIN for one-shot envelopes, so those slots would leak;
   * a slot that still holds unread data must never be reclaimed. */
  {
    int have_slot = 0;
    for (size_t i = 0; i < SLIVER_YAMUX_MAX_STREAMS; ++i) {
      if (!y->streams[i].used) {
        have_slot = 1;
        break;
      }
    }
    if (!have_slot) {
      sliver_yamux_stream_t *victim = NULL;
      sliver_yamux_stream_t *fallback = NULL;
      for (size_t i = 0; i < SLIVER_YAMUX_MAX_STREAMS; ++i) {
        sliver_yamux_stream_t *cur = &y->streams[i];
        if (!cur->used || !cur->closed_write) {
          continue;
        }
        if (cur->fin_received && cur->in_off >= cur->in.len) {
          if (victim == NULL || cur->id < victim->id) {
            victim = cur;
          }
        } else if (fallback == NULL || cur->id < fallback->id) {
          fallback = cur;
        }
      }
      if (victim == NULL) {
        victim = fallback;
      }
      if (victim != NULL) {
        release_stream(victim);
      }
    }
  }
  for (size_t i = 0; i < SLIVER_YAMUX_MAX_STREAMS; ++i) {
    if (!y->streams[i].used) {
      memset(&y->streams[i], 0, sizeof(y->streams[i]));
      y->streams[i].used = 1;
      y->streams[i].id = id;
      y->streams[i].send_window = SLIVER_YAMUX_INITIAL_WINDOW;
      sliver_buf_init(&y->streams[i].in);
      return &y->streams[i];
    }
  }
  return NULL;
}

int sliver_yamux_client(sliver_yamux_t *y, sliver_io_read_fn read_fn,
                        sliver_io_write_fn write_fn, void *ctx) {
  if (y == NULL || read_fn == NULL || write_fn == NULL) {
    return -1;
  }
  memset(y, 0, sizeof(*y));
  y->read_fn = read_fn;
  y->write_fn = write_fn;
  y->ctx = ctx;
  /* hashicorp/yamux: the *client* starts at 1 and steps by 2 (odd ids), the
   * server starts at 2 (even ids). Using even ids here collided with the
   * server's own streams, which corrupted tunnelled traffic and made accepts
   * swallow server requests. */
  y->next_stream_id = 1;
  y->write_lock = sliver_mutex_create();
  y->pump_lock = sliver_mutex_create();
  y->streams_lock = sliver_mutex_create();
  return 0;
}

void sliver_yamux_free(sliver_yamux_t *y) {
  if (y == NULL) {
    return;
  }
  for (size_t i = 0; i < SLIVER_YAMUX_MAX_STREAMS; ++i) {
    release_stream(&y->streams[i]);
  }
  if (y->write_lock != NULL) {
    sliver_mutex_destroy(y->write_lock);
    y->write_lock = NULL;
  }
  if (y->pump_lock != NULL) {
    sliver_mutex_destroy(y->pump_lock);
    y->pump_lock = NULL;
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_destroy(y->streams_lock);
    y->streams_lock = NULL;
  }
}

int sliver_yamux_open(sliver_yamux_t *y, uint32_t *stream_id) {
  uint32_t id;
  sliver_yamux_stream_t *s;
  if (y == NULL || y->failed) {
    return -1;
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_lock(y->streams_lock);
  }
  id = y->next_stream_id;
  y->next_stream_id += 2;
  if (y->local_count < SLIVER_YAMUX_MAX_STREAMS) {
    y->local_ids[y->local_count++] = id;
  } else {
    memmove(y->local_ids, y->local_ids + 1,
            sizeof(y->local_ids[0]) * (SLIVER_YAMUX_MAX_STREAMS - 1));
    y->local_ids[SLIVER_YAMUX_MAX_STREAMS - 1] = id;
  }
  s = alloc_stream(y, id);
  if (s == NULL) {
    if (y->streams_lock != NULL) {
      sliver_mutex_unlock(y->streams_lock);
    }
    return -1;
  }
  /* SYN window update: a new stream advertises a zero delta, exactly like
   * hashicorp/yamux (stream.sendWindowUpdate computes (max-bufLen)-recvWindow,
   * which is 0 for a fresh stream). Sending the full window here would inflate
   * the peer's send window to 2x what we actually buffer. */
  if (send_frame(y, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_SYN, id, NULL, 0) != 0) {
    y->failed = 1;
    if (y->streams_lock != NULL) {
      sliver_mutex_unlock(y->streams_lock);
    }
    return -1;
  }
  if (stream_id != NULL) {
    *stream_id = id;
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_unlock(y->streams_lock);
  }
  return 0;
}

static int replenish(sliver_yamux_t *y, uint32_t id, uint32_t consumed) {
  return send_frame(y, YAMUX_TYPE_WINDOW_UPDATE, 0, id, NULL, consumed);
}

static int yamux_pump_locked(sliver_yamux_t *y);

int sliver_yamux_pump(sliver_yamux_t *y) {
  int rc;
  if (y == NULL) {
    return -1;
  }
  if (y->pump_lock != NULL) {
    sliver_mutex_lock(y->pump_lock);
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_lock(y->streams_lock);
  }
  rc = yamux_pump_locked(y);
  if (y->streams_lock != NULL) {
    sliver_mutex_unlock(y->streams_lock);
  }
  if (y->pump_lock != NULL) {
    sliver_mutex_unlock(y->pump_lock);
  }
  return rc;
}

static int yamux_pump_locked(sliver_yamux_t *y) {
  uint8_t header[12];
  uint8_t type;
  uint16_t flags;
  uint32_t id, length;

  if (y == NULL || y->failed) {
    return -1;
  }
  {
    int rc = io_fill_header(y);
    if (rc == 1) {
      return 1; /* no complete frame yet */
    }
    if (rc != 0) {
      y->failed = 1;
      return -1;
    }
    memcpy(header, y->hdr_buf, sizeof(header));
    y->hdr_got = 0;
  }
  if (header[0] != YAMUX_VERSION) {
    y->failed = 1;
    return -1;
  }
  type = header[1];
  flags = get_u16_be(header + 2);
  id = get_u32_be(header + 4);
  length = get_u32_be(header + 8);

  switch (type) {
    case YAMUX_TYPE_DATA: {
      sliver_yamux_stream_t *s = find_stream(y, id);
      uint8_t chunk[SLIVER_YAMUX_MAX_FRAME];
      uint32_t remaining = length;
      if (s == NULL) {
        /* Unknown stream (already released): still replenish its window so the
         * peer's writes do not stall forever, then ask it to drop the stream. */
        while (remaining > 0) {
          uint32_t n = remaining > sizeof(chunk) ? (uint32_t)sizeof(chunk) : remaining;
          if (io_read_body(y, chunk, n) != 0) {
            y->failed = 1;
            return -1;
          }
          remaining -= n;
        }
        if (length != 0) {
          (void)replenish(y, id, length);
        }
        (void)send_frame(y, YAMUX_TYPE_DATA, YAMUX_FLAG_RST, id, NULL, 0);
        return 0;
      }
      /* Enforce the receive window we advertised, and compact the consumed
       * prefix so a long-lived stream does not grow without bound. */
      if (s->in_off != 0) {
        size_t live = s->in.len - s->in_off;
        memmove(s->in.data, s->in.data + s->in_off, live);
        s->in.len = live;
        s->in_off = 0;
      }
      while (remaining > 0) {
        uint32_t n = remaining > sizeof(chunk) ? (uint32_t)sizeof(chunk) : remaining;
        if (io_read_body(y, chunk, n) != 0) {
          y->failed = 1;
          return -1;
        }
        if (s->in.len + n > SLIVER_YAMUX_INITIAL_WINDOW * 2) {
          /* Over-window data: drop it and reset the stream instead of growing
           * the heap without limit. */
          remaining -= n;
          while (remaining > 0) {
            uint32_t m = remaining > sizeof(chunk) ? (uint32_t)sizeof(chunk) : remaining;
            if (io_read_body(y, chunk, m) != 0) {
              y->failed = 1;
              return -1;
            }
            remaining -= m;
          }
          (void)send_frame(y, YAMUX_TYPE_DATA, YAMUX_FLAG_RST, id, NULL, 0);
          release_stream(s);
          return 0;
        }
        if (sliver_buf_append(&s->in, chunk, n) != 0) {
          y->failed = 1;
          return -1;
        }
        remaining -= n;
      }
      if ((flags & YAMUX_FLAG_FIN) != 0) {
        s->fin_received = 1;
      }
      if (length != 0 && !s->fin_received) {
        (void)replenish(y, id, length);
      }
      maybe_release(s);
      return 0;
    }
    case YAMUX_TYPE_WINDOW_UPDATE: {
      sliver_yamux_stream_t *s = find_stream(y, id);
      if ((flags & YAMUX_FLAG_SYN) != 0) {
        if (find_stream(y, id) != NULL) {
          /* ACK of a stream we opened ourselves. */
          if (length != 0) {
            sliver_yamux_stream_t *own = find_stream(y, id);
            own->send_window = (UINT32_MAX - own->send_window < length)
                                   ? UINT32_MAX
                                   : own->send_window + length;
          }
          return 0;
        }
        if (is_local_id(y, id)) {
          /* ACK for one of our streams whose slot is already gone. Go keeps the
           * stream alive on its side; answering with a fresh ACK would make it
           * see a duplicate stream id and send goAway(protoErr), killing the
           * whole session. Just account for the window and move on. */
          return 0;
        }
        /* Peer initiated stream: acknowledge and remember it for accept. */
        if (alloc_stream(y, id) != NULL) {
          (void)send_frame(y, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_ACK, id, NULL, 0);
          pending_push(y, id);
        }
        return 0;
      }
      if (s != NULL) {
        /* hashicorp/yamux carries FIN and RST on windowUpdate frames
         * (stream.sendClose, session.incomingStream). */
        if ((flags & YAMUX_FLAG_RST) != 0) {
          release_stream(s);
          return 0;
        }
        if ((flags & YAMUX_FLAG_FIN) != 0) {
          s->fin_received = 1;
        }
        s->send_window = (UINT32_MAX - s->send_window < length) ? UINT32_MAX
                                                                 : s->send_window + length;
        maybe_release(s);
      }
      return 0;
    }
    case YAMUX_TYPE_PING: {
      if ((flags & YAMUX_FLAG_SYN) != 0) {
        (void)send_frame(y, YAMUX_TYPE_PING, YAMUX_FLAG_ACK, 0, NULL, length);
      }
      return 0;
    }
    case YAMUX_TYPE_GO_AWAY:
      y->go_away = 1;
      return 0;
    default:
      /* Unknown frame: drain payload and continue. */
      while (length > 0) {
        uint8_t chunk[256];
        uint32_t n = length > sizeof(chunk) ? (uint32_t)sizeof(chunk) : length;
        if (io_read_body(y, chunk, n) != 0) {
          y->failed = 1;
          return -1;
        }
        length -= n;
      }
      return 0;
  }
}

int sliver_yamux_write(sliver_yamux_t *y, uint32_t stream_id, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;
  sliver_yamux_stream_t *s;
  size_t sent = 0;
  uint64_t window_deadline = 0;

  if (y == NULL || y->failed || (buf == NULL && len != 0)) {
    return -1;
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_lock(y->streams_lock);
  }
  s = find_stream(y, stream_id);
  if (s == NULL) {
    LOG_ERROR("yamux: write to unknown stream %u (%u bytes)", stream_id, (unsigned)len);
    if (y->streams_lock != NULL) {
      sliver_mutex_unlock(y->streams_lock);
    }
    return -1;
  }
  while (sent < len) {
    size_t chunk;
    if (s->send_window == 0) {
      /* Bounded wait: a peer that stops replenishing the window must not pin
       * this sender (and the session tx lock it holds) forever. */
      if (window_deadline == 0) {
        window_deadline = sliver_now_ms() + SLIVER_YAMUX_WRITE_TIMEOUT_MS;
      } else if (sliver_now_ms() >= window_deadline) {
        LOG_ERROR("yamux: send window stalled (stream %u, %u/%u bytes)", stream_id,
                  (unsigned)sent, (unsigned)len);
        if (y->streams_lock != NULL) {
          sliver_mutex_unlock(y->streams_lock);
        }
        return -1;
      }
      /* Release streams_lock before pumping: pump takes pump_lock -> streams_lock. */
      if (y->streams_lock != NULL) {
        sliver_mutex_unlock(y->streams_lock);
      }
      {
        int prc = sliver_yamux_pump(y);
        if (prc < 0) {
          return -1;
        }
        if (prc == 1) {
          sliver_sleep_ms(1);
        }
      }
      if (y->streams_lock != NULL) {
        sliver_mutex_lock(y->streams_lock);
      }
      s = find_stream(y, stream_id);
      if (s == NULL) {
        if (y->streams_lock != NULL) {
          sliver_mutex_unlock(y->streams_lock);
        }
        return -1;
      }
      continue;
    }
    window_deadline = 0;
    chunk = len - sent;
    if (chunk > SLIVER_YAMUX_MAX_FRAME) {
      chunk = SLIVER_YAMUX_MAX_FRAME;
    }
    if (chunk > s->send_window) {
      chunk = s->send_window;
    }
    if (send_frame(y, YAMUX_TYPE_DATA, 0, stream_id, p + sent, (uint32_t)chunk) != 0) {
      LOG_ERROR("yamux: send_frame DATA failed (stream %u, chunk %u)", stream_id,
                (unsigned)chunk);
      y->failed = 1;
      if (y->streams_lock != NULL) {
        sliver_mutex_unlock(y->streams_lock);
      }
      return -1;
    }
    s->send_window -= (uint32_t)chunk;
    sent += chunk;
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_unlock(y->streams_lock);
  }
  return 0;
}

int sliver_yamux_close_write(sliver_yamux_t *y, uint32_t stream_id) {
  sliver_yamux_stream_t *s;
  int rc = 0;

  if (y == NULL || y->failed) {
    return -1;
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_lock(y->streams_lock);
  }
  s = find_stream(y, stream_id);
  if (s == NULL) {
    /* already released - nothing to half-close */
    if (y->streams_lock != NULL) {
      sliver_mutex_unlock(y->streams_lock);
    }
    return 0;
  }
  if (!s->closed_write) {
    /* FIN travels on a windowUpdate frame (hashicorp/yamux stream.sendClose). */
    if (send_frame(y, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_FIN, stream_id, NULL, 0) != 0) {
      y->failed = 1;
      rc = -1;
    } else {
      s->closed_write = 1;
      maybe_release(s);
    }
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_unlock(y->streams_lock);
  }
  return rc;
}

void sliver_yamux_forget(sliver_yamux_t *y, uint32_t stream_id) {
  if (y == NULL) {
    return;
  }
  if (y->streams_lock != NULL) {
    sliver_mutex_lock(y->streams_lock);
  }
  release_stream(find_stream(y, stream_id));
  if (y->streams_lock != NULL) {
    sliver_mutex_unlock(y->streams_lock);
  }
}

int sliver_yamux_accept(sliver_yamux_t *y, uint32_t *stream_id) {
  if (y == NULL || stream_id == NULL) {
    return -1;
  }
  for (;;) {
    if (y->failed || y->go_away) {
      return -1;
    }
    {
      int have = 0;
      if (y->streams_lock != NULL) {
        sliver_mutex_lock(y->streams_lock);
      }
      have = pending_pop(y, stream_id);
      if (y->streams_lock != NULL) {
        sliver_mutex_unlock(y->streams_lock);
      }
      if (have) {
        return 0;
      }
    }
    {
      int rc = sliver_yamux_pump(y);
      if (rc < 0) {
        return -1;
      }
      if (rc == 1) {
        sliver_sleep_ms(2); /* no data yet: do not spin the CPU */
      }
    }
  }
}

long sliver_yamux_read(sliver_yamux_t *y, uint32_t stream_id, void *buf, size_t len) {
  sliver_yamux_stream_t *s;
  size_t available;

  if (y == NULL || buf == NULL || len == 0) {
    return -1;
  }
  for (;;) {
    int prc;
    if (y->streams_lock != NULL) {
      sliver_mutex_lock(y->streams_lock);
    }
    s = find_stream(y, stream_id);
    if (s == NULL) {
      if (y->streams_lock != NULL) {
        sliver_mutex_unlock(y->streams_lock);
      }
      return -1;
    }
    available = s->in.len - s->in_off;
    if (available > 0) {
      size_t n = available < len ? available : len;
      memcpy(buf, s->in.data + s->in_off, n);
      s->in_off += n;
      if (y->streams_lock != NULL) {
        sliver_mutex_unlock(y->streams_lock);
      }
      return (long)n;
    }
    if (s->fin_received) {
      if (y->streams_lock != NULL) {
        sliver_mutex_unlock(y->streams_lock);
      }
      return 0;
    }
    if (y->streams_lock != NULL) {
      sliver_mutex_unlock(y->streams_lock);
    }
    prc = sliver_yamux_pump(y);
    if (prc < 0) {
      return -1;
    }
  }
}



















