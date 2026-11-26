/* tests/unit/test_age_keyex.c - sliver_age_keyex_to_server must be accepted by
 * the Go side (see tests/gzipfix keyex-check).
 *
 * SLIVER_KEYEX_FIXTURES holds keyex-server.pub, keyex-peer.pub, keyex-peer.id and
 * keyex-<name>.raw. This writes ours-keyex-<name>.bin:
 *   SHA256(peer.pub) || age_encrypt(server.pub, HMAC-SHA256(SHA256(peer.id), payload))
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/crypto.h"

#ifndef SLIVER_KEYEX_FIXTURES
#define SLIVER_KEYEX_FIXTURES "build"
#endif

static int failures = 0;

static unsigned char *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  unsigned char *buf;
  long size;
  if (f == NULL) {
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  size = ftell(f);
  if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  buf = (unsigned char *)malloc((size_t)size + 1);
  if (buf == NULL) {
    fclose(f);
    return NULL;
  }
  if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
    free(buf);
    fclose(f);
    return NULL;
  }
  buf[size] = 0;
  fclose(f);
  *len = (size_t)size;
  return buf;
}

static int write_file(const char *path, const void *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    return -1;
  }
  if (len != 0 && fwrite(data, 1, len, f) != len) {
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static char *read_text(const char *path) {
  size_t len = 0;
  unsigned char *buf = read_file(path, &len);
  (void)len;
  return (char *)buf;
}

int main(void) {
  static const char *names[] = {"k1", "k2", "k3"};
  char server_pub_path[512];
  char peer_pub_path[512];
  char peer_id_path[512];
  char *server_pub;
  char *peer_pub;
  char *peer_id;
  size_t i;

  (void)snprintf(server_pub_path, sizeof(server_pub_path), "%s/keyex-server.pub",
                 SLIVER_KEYEX_FIXTURES);
  (void)snprintf(peer_pub_path, sizeof(peer_pub_path), "%s/keyex-peer.pub",
                 SLIVER_KEYEX_FIXTURES);
  (void)snprintf(peer_id_path, sizeof(peer_id_path), "%s/keyex-peer.id",
                 SLIVER_KEYEX_FIXTURES);

  server_pub = read_text(server_pub_path);
  peer_pub = read_text(peer_pub_path);
  peer_id = read_text(peer_id_path);
  if (server_pub == NULL || peer_pub == NULL || peer_id == NULL) {
    printf("SKIP age_keyex (fixtures missing)\n");
    free(server_pub);
    free(peer_pub);
    free(peer_id);
    return 0;
  }

  /* Deriving the recipient from the identity must reproduce the fixture. */
  {
    char derived[128];
    if (sliver_age_peer_public(peer_id, derived, sizeof(derived)) != 0) {
      printf("FAIL cannot derive peer public key\n");
      failures++;
    } else if (strcmp(derived, peer_pub) != 0) {
      printf("FAIL peer public mismatch:\n  derived %s\n  fixture %s\n", derived, peer_pub);
      failures++;
    } else {
      printf("OK peer public key derivation\n");
    }
  }

  for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    char raw_path[512];
    char ours_path[512];
    unsigned char *raw;
    size_t raw_len = 0;

    (void)snprintf(raw_path, sizeof(raw_path), "%s/keyex-%s.raw", SLIVER_KEYEX_FIXTURES,
                   names[i]);
    (void)snprintf(ours_path, sizeof(ours_path), "%s/ours-keyex-%s.bin",
                   SLIVER_KEYEX_FIXTURES, names[i]);
    raw = read_file(raw_path, &raw_len);
    if (raw == NULL) {
      printf("SKIP %s (payload missing)\n", names[i]);
      continue;
    }
    {
      unsigned char *msg = NULL;
      size_t msg_len = 0;
      if (sliver_age_keyex_to_server(server_pub, peer_pub, peer_id, raw, raw_len, &msg,
                                     &msg_len) != 0) {
        printf("FAIL %s: key exchange failed\n", names[i]);
        failures++;
      } else if (write_file(ours_path, msg, msg_len) != 0) {
        printf("FAIL %s: cannot write %s\n", names[i], ours_path);
        failures++;
      } else {
        printf("OK %s: message %u bytes\n", names[i], (unsigned)msg_len);
      }
      free(msg);
    }
    free(raw);
  }

  free(server_pub);
  free(peer_pub);
  free(peer_id);

  if (failures != 0) {
    printf("test_age_keyex: %d failure(s)\n", failures);
    return 1;
  }
  printf("test_age_keyex: PASS\n");
  return 0;
}
