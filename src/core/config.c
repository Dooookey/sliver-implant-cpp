/* src/core/config.c - accessors over the generated build configuration. */
#include "sliver/config.h"

#include <stdio.h>
#include <string.h>

#include "implant_build_config.h"

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

int sliver_config_feature_mtls(void) { return SLIVER_FEATURE_MTLS; }
int sliver_config_feature_http(void) { return SLIVER_FEATURE_HTTP; }
int sliver_config_feature_dns(void) { return SLIVER_FEATURE_DNS; }
int sliver_config_feature_wg(void) { return SLIVER_FEATURE_WG; }
int sliver_config_feature_pivot(void) { return SLIVER_FEATURE_PIVOT; }

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
  return 0;
}
