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

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_PLATFORM_H */
