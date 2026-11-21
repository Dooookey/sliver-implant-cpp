/* src/entry/main.c - console entry point (M0 smoke build).
 *
 * M0 scope: prove the toolchain matrix, the configuration injection and the
 * platform abstraction work on Windows/Linux with MSVC/MinGW/Clang. The real
 * session/beacon loops land in M1.
 */
#include <stdio.h>
#include <string.h>

#include "sliver/config.h"
#include "sliver/log.h"
#include "sliver/platform.h"

#define SLIVER_SMOKE_ITERATIONS 20000

typedef struct {
  sliver_mutex_t *mutex;
  long counter;
} smoke_state_t;

static void smoke_worker(void *arg) {
  smoke_state_t *state = (smoke_state_t *)arg;
  for (int i = 0; i < SLIVER_SMOKE_ITERATIONS; ++i) {
    sliver_mutex_lock(state->mutex);
    state->counter += 1;
    sliver_mutex_unlock(state->mutex);
  }
}

static void print_banner(void) {
  (void)printf("sliver-cpp implant %s (build %s)\n", sliver_config_name(),
               sliver_config_build_id());
}

static void print_config(void) {
  (void)printf("  strategy         : %c\n", sliver_config_strategy());
  (void)printf("  c2 endpoints     : %u\n", (unsigned)sliver_config_c2_count());
  for (size_t i = 0; i < sliver_config_c2_count(); ++i) {
    (void)printf("    [%u] %s\n", (unsigned)i, sliver_config_c2_url(i));
  }
  (void)printf("  reconnect (ms)   : %lld\n",
               sliver_config_reconnect_interval_ns() / 1000000LL);
  (void)printf("  beacon interval  : %lld ms\n",
               sliver_config_beacon_interval_ns() / 1000000LL);
  (void)printf("  beacon jitter    : %lld ms\n",
               sliver_config_beacon_jitter_ns() / 1000000LL);
  (void)printf("  max conn errors  : %d\n", sliver_config_max_connection_errors());
  (void)printf("  transports       : mtls=%d http=%d dns=%d wg=%d pivot=%d\n",
               sliver_config_feature_mtls(), sliver_config_feature_http(),
               sliver_config_feature_dns(), sliver_config_feature_wg(),
               sliver_config_feature_pivot());
}

static int run_smoke(void) {
  smoke_state_t state;
  sliver_thread_t *threads[4];
  int rc = 0;

  state.mutex = sliver_mutex_create();
  state.counter = 0;
  if (state.mutex == NULL) {
    (void)fprintf(stderr, "mutex_create failed\n");
    return 1;
  }
  for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
    threads[i] = sliver_thread_create(smoke_worker, &state);
    if (threads[i] == NULL) {
      (void)fprintf(stderr, "thread_create failed\n");
      rc = 1;
      threads[i] = NULL;
    }
  }
  for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
    if (threads[i] != NULL && sliver_thread_join(threads[i]) != 0) {
      rc = 1;
    }
  }
  (void)printf("smoke: counter=%ld expected=%d\n", state.counter,
               SLIVER_SMOKE_ITERATIONS * 4);
  if (state.counter != (long)(SLIVER_SMOKE_ITERATIONS * 4)) {
    rc = 1;
  }
  sliver_mutex_destroy(state.mutex);
  return rc;
}

int main(int argc, char **argv) {
  char err[128];

  if (sliver_plat_init() != 0) {
    (void)fprintf(stderr, "platform init failed\n");
    return 1;
  }
  if (sliver_config_self_check(err, sizeof(err)) != 0) {
    (void)fprintf(stderr, "invalid configuration: %s\n", err);
    sliver_plat_cleanup();
    return 2;
  }

  if (argc > 1 && strcmp(argv[1], "--version") == 0) {
    print_banner();
    sliver_plat_cleanup();
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "--self-test") == 0) {
    int rc = run_smoke();
    sliver_plat_cleanup();
    return rc;
  }

  print_banner();
  print_config();
  LOG_INFO("layout ok; session/beacon loops arrive in M1");
  sliver_plat_cleanup();
  return 0;
}
