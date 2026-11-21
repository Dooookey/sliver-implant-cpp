/* src/core/config.c - accessors over the generated build configuration. */
#include "sliver/config.h"

#include <stdio.h>
#include <string.h>

#include "implant_build_config.h"

/* The generated TU defines this array; the enum in config.h must match. */
extern const char *const sliver_secret_values[];
extern const size_t sliver_secret_value_count;

const char *sliver_config_name(void) { return sliver_implant_name; }
const char *sliver_config_build_id(void) { return sliver_build_id_string; }

size_t sliver_config_c2_count(void) { return sliver_c2_url_count; }

const char *sliver_config_c2_url(size_t index) {
  if (index >= sliver_c2_url_count) {
    return NULL;
  }
  return sliver_c2_urls[index];
}

char sliver_config_strategy(void) { return SLIVER_CONNECTION_STRATEGY; }

long long sliver_config_reconnect_interval_ns(void) { return SLIVER_RECONNECT_INTERVAL_NS; }
long long sliver_config_beacon_interval_ns(void) { return SLIVER_BEACON_INTERVAL_NS; }
long long sliver_config_beacon_jitter_ns(void) { return SLIVER_BEACON_JITTER_NS; }
int sliver_config_max_connection_errors(void) { return SLIVER_MAX_CONNECTION_ERRORS; }
long long sliver_config_poll_timeout_ns(void) { return SLIVER_POLL_TIMEOUT_NS; }
int sliver_config_is_beacon(void) { return SLIVER_IS_BEACON; }

int sliver_config_feature_mtls(void) { return SLIVER_FEATURE_MTLS; }
int sliver_config_feature_http(void) { return SLIVER_FEATURE_HTTP; }
int sliver_config_feature_dns(void) { return SLIVER_FEATURE_DNS; }
int sliver_config_feature_wg(void) { return SLIVER_FEATURE_WG; }
int sliver_config_feature_pivot(void) { return SLIVER_FEATURE_PIVOT; }

const char *sliver_config_secret(sliver_secret_id_t id) {
  if ((int)id < 0 || (size_t)id >= sliver_secret_value_count) {
    return NULL;
  }
  if (sliver_secret_values[id] == NULL || sliver_secret_values[id][0] == '\0') {
    return NULL;
  }
  return sliver_secret_values[id];
}

size_t sliver_config_secret_length(sliver_secret_id_t id) {
  const char *value = sliver_config_secret(id);
  return value == NULL ? 0 : strlen(value);
}

static void set_err(char *err, size_t err_len, const char *msg) {
  if (err == NULL || err_len == 0) {
    return;
  }
  (void)snprintf(err, err_len, "%s", msg);
}

int sliver_config_self_check(char *err, size_t err_len) {
  if (sliver_config_name() == NULL || sliver_config_name()[0] == '\0') {
    set_err(err, err_len, "implant name is empty");
    return -1;
  }
  if (sliver_config_build_id() == NULL || sliver_config_build_id()[0] == '\0') {
    set_err(err, err_len, "build id is empty");
    return -1;
  }
  if (sliver_config_c2_count() == 0) {
    set_err(err, err_len, "no c2 endpoint configured");
    return -1;
  }
  for (size_t i = 0; i < sliver_config_c2_count(); ++i) {
    const char *url = sliver_config_c2_url(i);
    if (url == NULL || strstr(url, "://") == NULL) {
      set_err(err, err_len, "c2 endpoint is not a URI");
      return -1;
    }
  }
  if (sliver_config_reconnect_interval_ns() <= 0) {
    set_err(err, err_len, "reconnect interval must be positive");
    return -1;
  }
  if (sliver_config_beacon_interval_ns() <= 0) {
    set_err(err, err_len, "beacon interval must be positive");
    return -1;
  }
  if (sliver_config_max_connection_errors() <= 0) {
    set_err(err, err_len, "max connection errors must be positive");
    return -1;
  }
  if ((size_t)SLIVER_SECRET_COUNT != sliver_secret_value_count) {
    set_err(err, err_len, "secret slot count mismatch (generator/C header drift)");
    return -1;
  }
  return 0;
}
