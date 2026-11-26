/* tests/unit/test_encoders.c - compare the C encoders with util/encoders.
 *
 * Fixtures (build/enc-<name>-<tag>.out, build/enc-<name>.raw) come from Go's
 * util/encoders, so a mismatch means the wire format differs from the server.
 * Gzip is compared semantically (decode both sides) because compression output
 * is not required to be byte identical.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/crypto.h"

#ifndef SLIVER_ENCODER_FIXTURES
#define SLIVER_ENCODER_FIXTURES "build"
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
  fclose(f);
  *len = (size_t)size;
  return buf;
}

static void one(const char *name, const char *tag, sliver_encoder_kind_t kind, int textual) {
  char raw_path[512];
  char out_path[512];
  unsigned char *raw;
  unsigned char *want;
  size_t raw_len = 0;
  size_t want_len = 0;

  (void)snprintf(raw_path, sizeof(raw_path), "%s/enc-%s.raw", SLIVER_ENCODER_FIXTURES, name);
  (void)snprintf(out_path, sizeof(out_path), "%s/enc-%s-%s.out", SLIVER_ENCODER_FIXTURES, name,
                 tag);
  raw = read_file(raw_path, &raw_len);
  want = read_file(out_path, &want_len);
  if (raw == NULL || want == NULL) {
    printf("SKIP %s/%s (fixtures missing)\n", name, tag);
    free(raw);
    free(want);
    return;
  }

  /* decode(Go) must give the payload back */
  {
    unsigned char *dec = NULL;
    size_t dec_len = 0;
    if (sliver_encoder_decode(kind, want, want_len, &dec, &dec_len) != 0) {
      printf("FAIL %s/%s: cannot decode\n", name, tag);
      failures++;
    } else if (dec_len != raw_len || memcmp(dec, raw, raw_len) != 0) {
      printf("FAIL %s/%s: decoded %u bytes, expected %u\n", name, tag, (unsigned)dec_len,
             (unsigned)raw_len);
      failures++;
    }
    free(dec);
  }

  /* encode(payload) must match Go byte for byte (gzip: compare decoded content) */
  {
    unsigned char *enc = NULL;
    size_t enc_len = 0;
    if (sliver_encoder_encode(kind, raw, raw_len, &enc, &enc_len) != 0) {
      printf("FAIL %s/%s: cannot encode\n", name, tag);
      failures++;
    } else if (textual) {
      if (enc_len != want_len || memcmp(enc, want, want_len) != 0) {
        printf("FAIL %s/%s: encoded bytes differ (%u vs %u)\n", name, tag, (unsigned)enc_len,
               (unsigned)want_len);
        failures++;
      }
    } else {
      unsigned char *back = NULL;
      size_t back_len = 0;
      if (sliver_encoder_decode(kind, enc, enc_len, &back, &back_len) != 0 ||
          back_len != raw_len || memcmp(back, raw, raw_len) != 0) {
        printf("FAIL %s/%s: gzip round-trip mismatch\n", name, tag);
        failures++;
      }
      free(back);
    }
    free(enc);
  }

  free(raw);
  free(want);
}

int main(void) {
  static const char *names[] = {"e1", "e2", "e3"};
  size_t i;

  for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    one(names[i], "hex", SLIVER_ENCODER_HEX, 1);
    one(names[i], "b64", SLIVER_ENCODER_BASE64, 1);
    one(names[i], "b32", SLIVER_ENCODER_BASE32, 1);
    one(names[i], "gzip", SLIVER_ENCODER_GZIP, 0);
  }

  /* nonce <-> encoder selection mirrors EncoderFromNonce (id 0 = passthrough). */
  {
    sliver_encoder_kind_t kind = SLIVER_ENCODER_PNG;
    unsigned long long id = 1;
    unsigned long long nonce = 65537ull * 3ull;
    if (sliver_encoder_from_nonce(nonce, &kind, &id) != 0 || kind != SLIVER_ENCODER_NOP ||
        id != 0) {
      printf("FAIL nonce -> nop selection\n");
      failures++;
    }
    if (sliver_encoder_pick_nonce(SLIVER_ENCODER_NOP, &nonce) != 0 || nonce == 0 ||
        (nonce % 65537ull) != 0) {
      printf("FAIL pick nonce for nop\n");
      failures++;
    }
  }

  if (failures != 0) {
    printf("test_encoders: %d failure(s)\n", failures);
    return 1;
  }
  printf("test_encoders: PASS\n");
  return 0;
}
