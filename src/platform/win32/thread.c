/* src/platform/win32/thread.c - Win32 based platform layer.
 *
 * Deliberately uses raw Win32 primitives (no winpthreads, no CRT threads) so
 * MinGW-w64 cross builds behave exactly like MSVC builds.
 */
#include "sliver/platform.h"

#include <stdlib.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h> /* before windows.h: otherwise winsock.h conflicts */
#include <windows.h>

struct sliver_mutex {
  CRITICAL_SECTION cs;
  int initialized;
};

struct sliver_thread {
  HANDLE handle;
  sliver_thread_fn fn;
  void *arg;
};

int sliver_plat_init(void) {
  WSADATA wsa;
  return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) ? 0 : -1;
}

void sliver_plat_cleanup(void) { (void)WSACleanup(); }

uint64_t sliver_now_ms(void) { return (uint64_t)GetTickCount64(); }

void sliver_sleep_ms(uint32_t ms) { (void)Sleep((DWORD)ms); }

sliver_mutex_t *sliver_mutex_create(void) {
  sliver_mutex_t *m = (sliver_mutex_t *)calloc(1, sizeof(*m));
  if (m == NULL) {
    return NULL;
  }
  InitializeCriticalSection(&m->cs);
  m->initialized = 1;
  return m;
}

void sliver_mutex_destroy(sliver_mutex_t *m) {
  if (m == NULL) {
    return;
  }
  DeleteCriticalSection(&m->cs);
  free(m);
}

void sliver_mutex_lock(sliver_mutex_t *m) {
  if (m != NULL) {
    EnterCriticalSection(&m->cs);
  }
}

void sliver_mutex_unlock(sliver_mutex_t *m) {
  if (m != NULL) {
    LeaveCriticalSection(&m->cs);
  }
}

static DWORD WINAPI thread_trampoline(LPVOID opaque) {
  sliver_thread_t *t = (sliver_thread_t *)opaque;
  t->fn(t->arg);
  return 0;
}

sliver_thread_t *sliver_thread_create(sliver_thread_fn fn, void *arg) {
  sliver_thread_t *t;
  if (fn == NULL) {
    return NULL;
  }
  t = (sliver_thread_t *)calloc(1, sizeof(*t));
  if (t == NULL) {
    return NULL;
  }
  t->fn = fn;
  t->arg = arg;
  t->handle = CreateThread(NULL, 0, thread_trampoline, t, 0, NULL);
  if (t->handle == NULL) {
    free(t);
    return NULL;
  }
  return t;
}

int sliver_thread_join(sliver_thread_t *t) {
  int rc = -1;
  if (t == NULL) {
    return -1;
  }
  if (t->handle != NULL) {
    if (WaitForSingleObject(t->handle, INFINITE) == WAIT_OBJECT_0) {
      rc = 0;
    }
    (void)CloseHandle(t->handle);
  }
  free(t);
  return rc;
}
