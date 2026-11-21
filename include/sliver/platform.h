/* sliver/platform.h - the only place where Windows/POSIX differences live.
 *
 * Rules for the rest of the tree:
 *   - no <windows.h> outside src/platform/win32
 *   - no #ifdef _WIN32 in src/rpc, src/wire, src/transport, src/tunnel
 */
#ifndef SLIVER_PLATFORM_H
#define SLIVER_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sliver_mutex sliver_mutex_t;
typedef struct sliver_thread sliver_thread_t;
typedef struct sliver_socket sliver_socket_t;

typedef void (*sliver_thread_fn)(void *arg);

/* Process-wide init/cleanup (WSAStartup on Windows, no-op elsewhere). */
int sliver_plat_init(void);
void sliver_plat_cleanup(void);

uint64_t sliver_now_ms(void);
void sliver_sleep_ms(uint32_t ms);

sliver_mutex_t *sliver_mutex_create(void);
void sliver_mutex_destroy(sliver_mutex_t *m);
void sliver_mutex_lock(sliver_mutex_t *m);
void sliver_mutex_unlock(sliver_mutex_t *m);

sliver_thread_t *sliver_thread_create(sliver_thread_fn fn, void *arg);
/* Blocks until the thread finishes; destroys the handle. */
int sliver_thread_join(sliver_thread_t *t);

/* --- TCP sockets (blocking) -------------------------------------------- */
/* Returns NULL on failure. host may be a name or a literal address. */
sliver_socket_t *sliver_tcp_connect(const char *host, uint16_t port);
/* Returns the number of bytes transferred, or -1 on error. */
long sliver_socket_send(sliver_socket_t *s, const void *buf, size_t len);
long sliver_socket_recv(sliver_socket_t *s, void *buf, size_t len);
void sliver_socket_close(sliver_socket_t *s);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_PLATFORM_H */
