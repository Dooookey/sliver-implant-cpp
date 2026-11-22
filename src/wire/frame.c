/* src/wire/frame.c - signed envelope framing (see include/sliver/frame.h). */
#include "sliver/frame.h"

#include <stdlib.h>
#include <string.h>

#include "sliver/crypto.h"

#define SIGNING_SEED_PREFIX "env-signing-v1:"
#define MINISIGN_ALG_EDDSA 0x6445u

static void put_u32_le(unsigned char *p, uint32_t v) {
  p[0] = (unsigned char)(v & 0xff);
  p[1] = (unsigned char)((v >> 8) & 0xff);
  p[2] = (unsigned char)((v >> 16) & 0xff);
  p[3] = (unsigned char)((v >> 24) & 0xff);
}

static uint32_t get_u32_le(const unsigned char *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void put_u64_le(unsigned char *p, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
  }
}

int sliver_frame_signer_init(sliver_frame_signer_t *signer, const char *age_private_key) {
  unsigned char digest[32];
  unsigned char keyid_digest[32];
  size_t prefix_len = sizeof(SIGNING_SEED_PREFIX) - 1;
  size_t key_len;
  unsigned char *input;

  if (signer == NULL || age_private_key == NULL) {
    return -1;
  }
  memset(signer, 0, sizeof(*signer));
  key_len = strlen(age_private_key);
  input = (unsigned char *)malloc(prefix_len + key_len);
  if (input == NULL) {
    return -1;
  }
  memcpy(input, SIGNING_SEED_PREFIX, prefix_len);
  memcpy(input + prefix_len, age_private_key, key_len);
  if (sliver_sha256(input, prefix_len + key_len, digest) != 0) {
    free(input);
    return -1;
  }
  free(input);

  memcpy(signer->seed, digest, sizeof(signer->seed));
  if (sliver_ed25519_public_from_seed(signer->seed, signer->public_key) != 0) {
    return -1;
  }
  if (sliver_blake2b(signer->public_key, sizeof(signer->public_key), keyid_digest,
                     sizeof(keyid_digest)) != 0) {
    return -1;
  }
  signer->key_id = 0;
  for (int i = 7; i >= 0; --i) {
    signer->key_id = (signer->key_id << 8) | keyid_digest[i];
  }
  signer->ready = 1;
  return 0;
}

int sliver_frame_encode(const sliver_frame_signer_t *signer,
                        const void *envelope, size_t envelope_len,
                        sliver_buf_t *out) {
  unsigned char sig[SLIVER_FRAME_SIG_LEN];
  unsigned char len_le[4];
  size_t total;

  if (signer == NULL || !signer->ready || envelope == NULL || envelope_len == 0 ||
      envelope_len > SLIVER_FRAME_MAX_ENVELOPE || out == NULL) {
    return -1;
  }
  memset(sig, 0, sizeof(sig));
  sig[0] = (unsigned char)(MINISIGN_ALG_EDDSA & 0xff);
  sig[1] = (unsigned char)((MINISIGN_ALG_EDDSA >> 8) & 0xff);
  put_u64_le(sig + 2, signer->key_id);
  if (sliver_ed25519_sign(signer->seed, envelope, envelope_len, sig + 10) != 0) {
    return -1;
  }
  put_u32_le(len_le, (uint32_t)envelope_len);

  sliver_buf_init(out);
  total = SLIVER_FRAME_SIG_LEN + 4 + envelope_len;
  if (out->cap < total) {
    out->data = (unsigned char *)malloc(total);
    if (out->data == NULL) {
      out->failed = 1;
      return -1;
    }
    out->cap = total;
  }
  memcpy(out->data, sig, SLIVER_FRAME_SIG_LEN);
  memcpy(out->data + SLIVER_FRAME_SIG_LEN, len_le, 4);
  memcpy(out->data + SLIVER_FRAME_SIG_LEN + 4, envelope, envelope_len);
  out->len = total;
  return 0;
}

static int read_full(sliver_io_read_fn read_fn, void *ctx, void *buf, size_t len) {
  size_t got = 0;
  while (got < len) {
    long n = read_fn(ctx, (unsigned char *)buf + got, len - got);
    if (n <= 0) {
      return -1;
    }
    got += (size_t)n;
  }
  return 0;
}

static int write_full(sliver_io_write_fn write_fn, void *ctx, const void *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    long n = write_fn(ctx, (const unsigned char *)buf + sent, len - sent);
    if (n <= 0) {
      return -1;
    }
    sent += (size_t)n;
  }
  return 0;
}

int sliver_frame_write(sliver_frame_signer_t *signer, sliver_io_write_fn write_fn, void *ctx,
                       const void *envelope, size_t envelope_len) {
  sliver_buf_t frame;
  int rc;
  if (write_fn == NULL) {
    return -1;
  }
  if (sliver_frame_encode(signer, envelope, envelope_len, &frame) != 0) {
    return -1;
  }
  rc = write_full(write_fn, ctx, frame.data, frame.len);
  sliver_buf_free(&frame);
  return rc;
}

int sliver_frame_read(const char *server_pubkey_text, sliver_io_read_fn read_fn, void *ctx,
                      sliver_buf_t *env_out) {
  unsigned char sig[SLIVER_FRAME_SIG_LEN];
  unsigned char len_le[4];
  uint32_t env_len;

  if (server_pubkey_text == NULL || read_fn == NULL || env_out == NULL) {
    return -1;
  }
  sliver_buf_init(env_out);
  if (read_full(read_fn, ctx, sig, sizeof(sig)) != 0) {
    return -1;
  }
  if (read_full(read_fn, ctx, len_le, sizeof(len_le)) != 0) {
    return -1;
  }
  env_len = get_u32_le(len_le);
  if (env_len == 0 || env_len > SLIVER_FRAME_MAX_ENVELOPE) {
    /* Drain the oversized payload so the stream stays framed, then report it. */
    if (env_len != 0 && env_len <= (64u * 1024u * 1024u)) {
      unsigned char discard[512];
      uint32_t left = env_len;
      while (left > 0) {
        uint32_t n = left > sizeof(discard) ? (uint32_t)sizeof(discard) : left;
        if (read_full(read_fn, ctx, discard, n) != 0) {
          return -1;
        }
        left -= n;
      }
    }
    return -2;
  }
  env_out->data = (unsigned char *)malloc(env_len);
  if (env_out->data == NULL) {
    return -1;
  }
  env_out->cap = env_len;
  env_out->len = env_len;
  if (read_full(read_fn, ctx, env_out->data, env_len) != 0) {
    sliver_buf_free(env_out);
    return -1;
  }
  if (sliver_minisign_raw_verify(server_pubkey_text, sig, env_out->data, env_len) != 0) {
    sliver_buf_free(env_out);
    return -2;
  }
  return 0;
}
