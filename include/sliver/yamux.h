/* sliver/yamux.h - client side of the hashicorp/yamux protocol.
 *
 * Sliver uses yamux (protoVersion 0) after the transport handshake and writes
 * exactly one Envelope per stream. Header layout (12 bytes, big endian fields):
 *
 *   [0] version (0)  [1] type  [2..3] flags  [4..7] streamID  [8..11] length
 *
 *   type: 0 data, 1 windowUpdate, 2 ping, 3 goAway
 *   flags: SYN=1, ACK=2, FIN=4, RST=8
 *
 * The client opens even stream ids (2, 4, ...), the server odd ones, the
 * initial stream window is 256 KiB.
 */
#ifndef SLIVER_YAMUX_H
#define SLIVER_YAMUX_H

#include <stddef.h>
#include <stdint.h>

#include "sliver/frame.h"
#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLIVER_YAMUX_INITIAL_WINDOW (256u * 1024u)
#define SLIVER_YAMUX_MAX_STREAMS 1024
#define SLIVER_YAMUX_MAX_FRAME (64u * 1024u)

typedef struct {
  uint32_t id;
  int used;
  int fin_received;
  int closed_write;
  uint32_t send_window;
  sliver_buf_t in;
  size_t in_off;
} sliver_yamux_stream_t;

typedef struct {
  sliver_io_read_fn read_fn;
  sliver_io_write_fn write_fn;
  void *ctx;
  sliver_yamux_stream_t streams[SLIVER_YAMUX_MAX_STREAMS];
  uint32_t next_stream_id;
  int failed;
  int go_away;
  uint32_t pending_accept;
  /* Ids we opened ourselves: a SYN/window-update on them is not a peer stream
   * (the slot may already be released), it is the ACK of our own SYN. */
  uint32_t local_ids[SLIVER_YAMUX_MAX_STREAMS];
  size_t local_count;
} sliver_yamux_t;

int sliver_yamux_client(sliver_yamux_t *y, sliver_io_read_fn read_fn,
                        sliver_io_write_fn write_fn, void *ctx);
void sliver_yamux_free(sliver_yamux_t *y);

/* Opens a new stream (sends the SYN window update). Returns 0 on success. */
int sliver_yamux_open(sliver_yamux_t *y, uint32_t *stream_id);
/* Writes len bytes; returns 0 on success. */
int sliver_yamux_write(sliver_yamux_t *y, uint32_t stream_id, const void *buf, size_t len);
/* Half-closes the stream (FIN). */
int sliver_yamux_close_write(sliver_yamux_t *y, uint32_t stream_id);
/* Frees our local bookkeeping for a write-only stream (called right after the
 * FIN of a one-shot envelope: the peer's own FIN may never arrive, and leaking
 * the slot eventually blocks every new stream). */
void sliver_yamux_forget(sliver_yamux_t *y, uint32_t stream_id);
/* Reads up to len bytes; >0 data, 0 clean EOF, -1 error. */
long sliver_yamux_read(sliver_yamux_t *y, uint32_t stream_id, void *buf, size_t len);
/* Pumps one incoming frame (used by blocking helpers and by the session loop). */
int sliver_yamux_pump(sliver_yamux_t *y);
/* Blocks until the peer opens a stream; returns 0 and its id on success. */
int sliver_yamux_accept(sliver_yamux_t *y, uint32_t *stream_id);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_YAMUX_H */

