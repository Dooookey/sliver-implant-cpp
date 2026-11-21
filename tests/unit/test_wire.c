/* tests/unit/test_wire.c - protobuf, signed frame and golden-vector tests. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/crypto.h"
#include "sliver/frame.h"
#include "sliver/proto.h"

static int g_failures = 0;

#define CHECK(cond, msg)                                               \
  do {                                                                 \
    if (!(cond)) {                                                     \
      (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, msg); \
      g_failures += 1;                                                 \
    }                                                                  \
  } while (0)

static void to_hex(const unsigned char *buf, size_t len, char *out) {
  static const char *d = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = d[buf[i] >> 4];
    out[2 * i + 1] = d[buf[i] & 0xf];
  }
  out[2 * len] = '\0';
}

static void from_hex(const char *hex, unsigned char *out, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    unsigned int v = 0;
    (void)sscanf(hex + 2 * i, "%2x", &v);
    out[i] = (unsigned char)v;
  }
}

static void b64_encode(const unsigned char *in, size_t len, char *out) {
  static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0, i = 0;
  while (i + 2 < len) {
    unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    out[o++] = t[(v >> 6) & 63];
    out[o++] = t[v & 63];
    i += 3;
  }
  if (i + 1 == len) {
    unsigned v = (unsigned)in[i] << 16;
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    out[o++] = '=';
    out[o++] = '=';
  } else if (i + 2 == len) {
    unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    out[o++] = t[(v >> 6) & 63];
    out[o++] = '=';
  }
  out[o] = '\0';
}

/* --- protobuf ----------------------------------------------------------- */

static void test_envelope_golden(void) {
  sliver_buf_t b;
  char hex[64];
  const unsigned char *data = (const unsigned char *)"abc";

  sliver_buf_init(&b);
  CHECK(sliver_envelope_encode(&b, 1, 1, data, 3) == 0, "envelope encode");
  to_hex(b.data, b.len, hex);
  /* field1 varint 1 | field2 varint 1 | field3 bytes len 3 "abc" */
  CHECK(strcmp(hex, "080110011a03616263") == 0, "envelope golden bytes");
  sliver_buf_free(&b);
}

static void test_envelope_roundtrip_and_unknown_fields(void) {
  sliver_buf_t b;
  sliver_envelope_t env;
  const unsigned char payload[] = {0x00, 0xff, 0x7f};

  sliver_buf_init(&b);
  CHECK(sliver_envelope_encode(&b, -42, 22, payload, sizeof(payload)) == 0, "envelope encode");
  /* append an unknown field 99, varint 1 -> should be skipped */
  CHECK(sliver_buf_put_tag(&b, 99, 0) == 0 && sliver_buf_put_varint(&b, 1) == 0,
        "append unknown field");
  CHECK(sliver_envelope_decode(b.data, b.len, &env) == 0, "envelope decode");
  CHECK(env.id == -42, "envelope id");
  CHECK(env.type == 22, "envelope type");
  CHECK(env.data_len == sizeof(payload) && memcmp(env.data, payload, sizeof(payload)) == 0,
        "envelope payload");
  sliver_buf_free(&b);
}

static void test_register_roundtrip(void) {
  sliver_register_t in, out;
  sliver_buf_t b;

  memset(&in, 0, sizeof(in));
  strcpy(in.name, "cpp-implant");
  strcpy(in.hostname, "WORKSTATION");
  strcpy(in.uuid, "0f8fad5b-d9cb-469f-a165-70867728950e");
  strcpy(in.username, "alice");
  strcpy(in.uid, "1000");
  strcpy(in.gid, "1000");
  strcpy(in.os, "windows");
  strcpy(in.arch, "amd64");
  in.pid = 4242;
  strcpy(in.filename, "C:\\Temp\\implant.exe");
  strcpy(in.active_c2, "mtls://10.0.0.5:8888");
  strcpy(in.version, "1.7.8");
  in.reconnect_interval = 60000000000LL;
  strcpy(in.config_id, "build-1");
  in.peer_id = 7;
  strcpy(in.locale, "en-US");
  in.capabilities = 3;

  sliver_buf_init(&b);
  CHECK(sliver_register_encode(&b, &in) == 0, "register encode");
  CHECK(sliver_register_decode(b.data, b.len, &out) == 0, "register decode");
  CHECK(strcmp(out.name, in.name) == 0, "register name");
  CHECK(strcmp(out.hostname, in.hostname) == 0, "register hostname");
  CHECK(out.pid == in.pid, "register pid");
  CHECK(out.reconnect_interval == in.reconnect_interval, "register reconnect");
  CHECK(strcmp(out.active_c2, in.active_c2) == 0, "register c2");
  CHECK(strcmp(out.config_id, in.config_id) == 0, "register config id");
  CHECK(out.capabilities == in.capabilities, "register capabilities");
  sliver_buf_free(&b);
}

static void test_ping_roundtrip(void) {
  sliver_buf_t b;
  int32_t nonce = 0;
  sliver_buf_init(&b);
  CHECK(sliver_ping_encode(&b, 31337) == 0, "ping encode");
  CHECK(sliver_ping_decode_nonce(b.data, b.len, &nonce) == 0, "ping decode");
  CHECK(nonce == 31337, "ping nonce");
  sliver_buf_free(&b);
}

/* --- frame -------------------------------------------------------------- */

/* Vectors generated with tests/frame-vecgen (Go standard library ed25519). */
static const char *kAgePrivate =
    "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST";
static const char *kGoPublicKey =
    "617d5303b1b7c8290aa8f49a88fdd475135d75b60de404efbcf062e888a21d19";
static const char *kGoSignature =
    "8c06cae71a4e0609a0714af274ed05856a9833c52114a3e9013fd6607f24d387"
    "df3f5a5fe0d169dbd7a6bf9530e24762683d236cdc1a730a206fc247290db706";
static const char *kFrameMessage = "sliver-frame-test";

typedef struct {
  const unsigned char *data;
  size_t len;
  size_t pos;
} mem_reader_t;

static long mem_read(void *ctx, void *buf, size_t len) {
  mem_reader_t *r = (mem_reader_t *)ctx;
  size_t avail = r->len - r->pos;
  size_t n = len < avail ? len : avail;
  if (n == 0) {
    return -1;
  }
  memcpy(buf, r->data + r->pos, n);
  r->pos += n;
  return (long)n;
}

static void build_minisign_pubkey_text(const unsigned char pub[32], char *out, size_t cap) {
  unsigned char raw[42];
  char b64[64];
  uint64_t key_id = 0;
  CHECK(sliver_minisign_keyid(pub, &key_id) == 0, "minisign keyid");
  raw[0] = 0x45; /* 0x6445 LE */
  raw[1] = 0x64;
  for (int i = 0; i < 8; ++i) {
    raw[2 + i] = (unsigned char)((key_id >> (8 * i)) & 0xff);
  }
  memcpy(raw + 10, pub, 32);
  b64_encode(raw, sizeof(raw), b64);
  (void)snprintf(out, cap, "untrusted comment: minisign public key: %016llX\n%s\n",
                 (unsigned long long)key_id, b64);
}

static void test_signer_vectors(void) {
  sliver_frame_signer_t signer;
  unsigned char want_pub[32], want_sig[64];
  char hex[160];

  CHECK(sliver_frame_signer_init(&signer, kAgePrivate) == 0, "signer init");
  from_hex(kGoPublicKey, want_pub, 32);
  CHECK(memcmp(signer.public_key, want_pub, 32) == 0, "signer public key matches Go");

  CHECK(sliver_ed25519_sign(signer.seed, kFrameMessage, strlen(kFrameMessage), want_sig) == 0,
        "sign");
  to_hex(want_sig, 64, hex);
  CHECK(strcmp(hex, kGoSignature) == 0, "signature matches Go");

  /* key id must match BLAKE2b-256(pub)[:8] little endian */
  {
    unsigned char digest[32];
    uint64_t expect = 0;
    CHECK(sliver_blake2b(signer.public_key, 32, digest, sizeof(digest)) == 0, "blake2b");
    for (int i = 7; i >= 0; --i) {
      expect = (expect << 8) | digest[i];
    }
    CHECK(signer.key_id == expect, "key id derivation");
  }
}

static void test_frame_roundtrip(void) {
  sliver_frame_signer_t signer;
  sliver_buf_t env, frame, decoded;
  char pub_text[256];
  mem_reader_t reader;
  int rc;

  CHECK(sliver_frame_signer_init(&signer, kAgePrivate) == 0, "signer init");
  build_minisign_pubkey_text(signer.public_key, pub_text, sizeof(pub_text));

  sliver_buf_init(&env);
  CHECK(sliver_envelope_encode(&env, 1, SLIVER_MSG_PING, "x", 1) == 0, "envelope");
  CHECK(sliver_frame_encode(&signer, env.data, env.len, &frame) == 0, "frame encode");
  CHECK(frame.len == SLIVER_FRAME_SIG_LEN + 4 + env.len, "frame length");
  CHECK(frame.data[0] == 0x45 && frame.data[1] == 0x64, "frame algorithm tag");
  CHECK(frame.data[SLIVER_FRAME_SIG_LEN] == (unsigned char)env.len, "frame length prefix");

  reader.data = frame.data;
  reader.len = frame.len;
  reader.pos = 0;
  CHECK(sliver_frame_read(pub_text, mem_read, &reader, &decoded) == 0, "frame read");
  CHECK(decoded.len == env.len && memcmp(decoded.data, env.data, env.len) == 0,
        "frame payload roundtrip");
  sliver_buf_free(&decoded);

  /* tampering with the signature must be rejected */
  reader.pos = 0;
  frame.data[20] ^= 0xff;
  rc = sliver_frame_read(pub_text, mem_read, &reader, &decoded);
  CHECK(rc == -2, "tampered frame must fail verification");

  sliver_buf_free(&env);
  sliver_buf_free(&frame);
}

int main(void) {
  test_envelope_golden();
  test_envelope_roundtrip_and_unknown_fields();
  test_register_roundtrip();
  test_ping_roundtrip();
  test_signer_vectors();
  test_frame_roundtrip();

  if (g_failures != 0) {
    (void)fprintf(stderr, "%d wire assertion(s) failed\n", g_failures);
    return 1;
  }
  (void)printf("wire ok (protobuf envelope/register/ping, frame sign/verify, Go vectors)\n");
  return 0;
}
