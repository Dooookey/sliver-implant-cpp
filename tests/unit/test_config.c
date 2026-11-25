/* tests/unit/test_config.c - configuration injection assertions.
 *
 * These are the C side of the "golden vector" contract described in
 * docs/refactor/01: if the server renders a config, the implant must observe
 * exactly those values.
 */
#include <stdio.h>
#include <string.h>

#include "sliver/config.h"

static int g_failures = 0;

#define CHECK(cond, msg)                                        \
  do {                                                          \
    if (!(cond)) {                                              \
      (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, msg); \
      g_failures += 1;                                          \
    }                                                           \
  } while (0)

int main(void) {
  char err[128];
  char tiny[8];

  CHECK(sliver_config_name() != NULL && sliver_config_name()[0] != '\0',
        "implant name must be injected");
  CHECK(sliver_config_build_id() != NULL && sliver_config_build_id()[0] != '\0',
        "build id must be injected");
  CHECK(sliver_config_c2_count() >= 1, "at least one c2 endpoint");
  CHECK(sliver_config_c2_url(0) != NULL, "c2[0] must exist");
  CHECK(sliver_config_c2_url(sliver_config_c2_count()) == NULL,
        "out of range c2 index must return NULL");
  CHECK(sliver_config_reconnect_interval_ns() > 0, "reconnect interval positive");
  /* Session builds carry a zero beacon interval (the server writes 0 when
   * IsBeacon is false); only beacon builds require a positive one. dev.json
   * mirrors the session shape, so this also pins the self_check regression. */
  CHECK(!sliver_config_is_beacon() || sliver_config_beacon_interval_ns() > 0,
        "beacon builds need a positive interval");

  /* HTTP(S) C2 profile accessors (data only; no runtime consumer yet). */
  {
    sliver_http_c2_t h;
    size_t n = 0;
    const sliver_http_header_t *hdrs;
    CHECK(sliver_config_http_c2(&h) == 1, "http profile must be present in dev.json");
    CHECK(h.present == 1, "http present flag");
    CHECK(h.user_agent != NULL && h.user_agent[0] != '\0', "http user agent");
    CHECK(h.nonce_query_arg_len > 0, "http nonce length");
    CHECK(h.max_path_length >= h.min_path_length, "http path length range");
    hdrs = sliver_config_http_headers(&n);
    CHECK(hdrs != NULL && n == 2, "http headers count");
    CHECK(n == 0 || (hdrs[0].method != NULL && hdrs[0].name != NULL),
          "http header fields");
    (void)sliver_config_http_url_parameters(&n);
    CHECK(n == 1, "http url parameters count");
    (void)sliver_config_http_extensions(&n);
    CHECK(n == 2, "http extensions count");
    {
      const sliver_http_path_seg_t *segs = sliver_config_http_path_segments(&n);
      CHECK(segs != NULL && n == 2, "http path segments count");
      CHECK(n < 2 || (segs[0].is_file == 0 && segs[1].is_file == 1),
            "http path segment is_file flags");
    }
  }
  CHECK(sliver_config_max_connection_errors() > 0, "max connection errors positive");

  err[0] = '\0';
  CHECK(sliver_config_self_check(err, sizeof(err)) == 0, "config must be self-consistent");
  CHECK(err[0] == '\0', "no error text on success");

  /* Secret slot table must match the generated TU (guards header/generator drift). */
  CHECK(sliver_config_secret_length(SLIVER_SECRET_COUNT) == 0,
        "out of range secret slot must be empty");
  CHECK(sliver_config_secret(SLIVER_SECRET_PEER_PUBLIC_KEY) == NULL ||
            sliver_config_secret_length(SLIVER_SECRET_PEER_PUBLIC_KEY) > 0,
        "secret accessor must return NULL or a non-empty value");
  CHECK(sliver_config_is_beacon() == 0 || sliver_config_is_beacon() == 1,
        "beacon flag must be boolean");

  tiny[0] = '\0';
  (void)sliver_config_self_check(tiny, sizeof(tiny));
  CHECK(strlen(tiny) < sizeof(tiny), "error message must stay truncated");

  if (g_failures != 0) {
    (void)fprintf(stderr, "%d assertion(s) failed\n", g_failures);
    return 1;
  }
  (void)printf("config injection ok: %s / %s / %u endpoint(s)\n", sliver_config_name(),
               sliver_config_build_id(), (unsigned)sliver_config_c2_count());
  return 0;
}
