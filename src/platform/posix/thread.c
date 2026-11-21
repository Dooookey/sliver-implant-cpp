/* src/platform/posix/thread.c - pthread based platform layer. */
#if !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE < 200809L)
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L /* clock_gettime, nanosleep */
#endif

#include "sliver/platform.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct sliver_mutex {
  pthread_mutex_t handle;
};

struct sliver_thread {
  pthread_t handle;
  int started;
  sliver_thread_fn fn;
  void *arg;
};

int sliver_plat_init(void) { return 0; }
void sliver_plat_cleanup(void) {}

uint64_t sliver_now_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

void sliver_sleep_ms(uint32_t ms) {
  struct timespec req;
  req.tv_sec = (time_t)(ms / 1000U);
  req.tv_nsec = (long)(ms % 1000U) * 1000000L;
  while (nanosleep(&req, &req) != 0 && errno == EINTR) {
  }
}

sliver_mutex_t *sliver_mutex_create(void) {
  sliver_mutex_t *m = (sliver_mutex_t *)calloc(1, sizeof(*m));
  if (m == NULL) {
    return NULL;
  }
  if (pthread_mutex_init(&m->handle, NULL) != 0) {
    free(m);
    return NULL;
  }
  return m;
}

void sliver_mutex_destroy(sliver_mutex_t *m) {
  if (m == NULL) {
    return;
  }
  (void)pthread_mutex_destroy(&m->handle);
  free(m);
}

void sliver_mutex_lock(sliver_mutex_t *m) {
  if (m != NULL) {
    (void)pthread_mutex_lock(&m->handle);
  }
}

void sliver_mutex_unlock(sliver_mutex_t *m) {
  if (m != NULL) {
    (void)pthread_mutex_unlock(&m->handle);
  }
}

static void *thread_trampoline(void *opaque) {
  sliver_thread_t *t = (sliver_thread_t *)opaque;
  t->fn(t->arg);
  return NULL;
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
  if (pthread_create(&t->handle, NULL, thread_trampoline, t) != 0) {
    free(t);
    return NULL;
  }
  t->started = 1;
  return t;
}

int sliver_thread_join(sliver_thread_t *t) {
  int rc = -1;
  if (t == NULL) {
    return -1;
  }
  if (t->started) {
    rc = (pthread_join(t->handle, NULL) == 0) ? 0 : -1;
  }
  free(t);
  return rc;
}
