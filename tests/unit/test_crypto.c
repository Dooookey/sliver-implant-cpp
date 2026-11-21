/* tests/unit/test_crypto.c - known-answer tests for the crypto layer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sliver/crypto.h"

static int g_failures = 0;

#define CHECK(cond, msg)                                              \
  do {                                                                \
    if (!(cond)) {                                                    \
      (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, msg); \
      g_failures += 1;                                                \
    }                                                                 \
  } while (0)

static void hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
  for (size_t i = 0; i < out_len; ++i) {
    unsigned int v = 0;
    (void)sscanf(hex + 2 * i, "%2x", &v);
    out[i] = (unsigned char)v;
  }
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
  (void)fprintf(stderr, "%s=", label);
  for (size_t i = 0; i < len; ++i) {
    (void)fprintf(stderr, "%02x", buf[i]);
  }
  (void)fputc('\n', stderr);
}

static void test_sha256(void) {
  unsigned char out[32];
  const char *expect = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  unsigned char want[32];
  hex_to_bytes(expect, want, sizeof(want));
  CHECK(sliver_sha256("abc", 3, out) == 0, "sha256 rc");
  if (memcmp(out, want, 32) != 0) {
    print_hex("sha256", out, 32);
    CHECK(0, "sha256(abc) mismatch");
  }
}

static void test_blake2b(void) {
  unsigned char out[64];
  const char *expect =
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
  unsigned char want[64];
  hex_to_bytes(expect, want, sizeof(want));
  CHECK(sliver_blake2b("abc", 3, out, sizeof(out)) == 0, "blake2b rc");
  if (memcmp(out, want, 64) != 0) {
    print_hex("blake2b512", out, 64);
    CHECK(0, "blake2b-512(abc) mismatch");
  }
}

static void test_ed25519_rfc8032(void) {
  const char *seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const char *pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const char *sig_hex =
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
  unsigned char seed[32], pk[32], want_pk[32], sig[64], want_sig[64];

  hex_to_bytes(seed_hex, seed, 32);
  hex_to_bytes(pk_hex, want_pk, 32);
  hex_to_bytes(sig_hex, want_sig, 64);

  CHECK(sliver_ed25519_public_from_seed(seed, pk) == 0, "ed25519 pub rc");
  CHECK(memcmp(pk, want_pk, 32) == 0, "ed25519 public key mismatch");

  CHECK(sliver_ed25519_sign(seed, "", 0, sig) == 0, "ed25519 sign rc");
  CHECK(memcmp(sig, want_sig, 64) == 0, "ed25519 signature mismatch");
  CHECK(sliver_ed25519_verify(want_pk, "", 0, want_sig) == 0, "ed25519 verify rc");

  want_sig[0] ^= 0xff;
  CHECK(sliver_ed25519_verify(want_pk, "", 0, want_sig) != 0, "ed25519 must reject tampered sig");
}

static void test_x25519_rfc7748(void) {
  const char *alice_sk_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
  const char *alice_pk_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  const char *bob_sk_hex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
  const char *bob_pk_hex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
  const char *shared_hex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

  unsigned char alice_sk[32], alice_pk[32], bob_sk[32], bob_pk[32], want[32], got[32];

  hex_to_bytes(alice_sk_hex, alice_sk, 32);
  hex_to_bytes(alice_pk_hex, alice_pk, 32);
  hex_to_bytes(bob_sk_hex, bob_sk, 32);
  hex_to_bytes(bob_pk_hex, bob_pk, 32);
  hex_to_bytes(shared_hex, want, 32);

  CHECK(sliver_x25519_shared(alice_sk, bob_pk, got) == 0, "x25519 rc");
  if (memcmp(got, want, 32) != 0) {
    print_hex("shared", got, 32);
    CHECK(0, "x25519 shared secret mismatch");
  }

  /* public key derivation must match the RFC as well */
  {
    unsigned char base[32];
    memset(base, 0, sizeof(base));
    base[0] = 9;
    CHECK(sliver_x25519_shared(alice_sk, base, got) == 0, "x25519 pub rc");
    CHECK(memcmp(got, alice_pk, 32) == 0, "x25519 public key mismatch");
    CHECK(sliver_x25519_shared(bob_sk, base, got) == 0, "x25519 pub rc (bob)");
    CHECK(memcmp(got, bob_pk, 32) == 0, "x25519 public key mismatch (bob)");
  }
}

static void test_chachapoly_roundtrip(void) {
  unsigned char key[32], nonce[12], aad[16];
  unsigned char plain[64];
  unsigned char sealed[64 + 16];
  unsigned char opened[64];

  memset(key, 0x42, sizeof(key));
  memset(nonce, 0x07, sizeof(nonce));
  memset(aad, 0x50, sizeof(aad));
  for (size_t i = 0; i < sizeof(plain); ++i) {
    plain[i] = (unsigned char)i;
  }

  CHECK(sliver_chachapoly_seal(key, nonce, aad, sizeof(aad), plain, sizeof(plain), sealed) == 0,
        "chachapoly seal");
  CHECK(sliver_chachapoly_open(key, nonce, aad, sizeof(aad), sealed, sizeof(sealed), opened) == 0,
        "chachapoly open");
  CHECK(memcmp(plain, opened, sizeof(plain)) == 0, "chachapoly roundtrip mismatch");

  sealed[0] ^= 0x01;
  CHECK(sliver_chachapoly_open(key, nonce, aad, sizeof(aad), sealed, sizeof(sealed), opened) != 0,
        "chachapoly must reject tampered ciphertext");
}

static void test_bech32_roundtrip(void) {
  unsigned char data[32];
  char encoded[128];
  char upper[128];
  unsigned char decoded[32];
  size_t decoded_len = sizeof(decoded);

  for (size_t i = 0; i < sizeof(data); ++i) {
    data[i] = (unsigned char)(i * 7 + 1);
  }
  CHECK(sliver_bech32_encode("age", data, sizeof(data), encoded, sizeof(encoded)) == 0, "bech32 encode");
  CHECK(sliver_bech32_decode(encoded, decoded, &decoded_len) == 0, "bech32 decode");
  CHECK(decoded_len == sizeof(data) && memcmp(decoded, data, sizeof(data)) == 0, "bech32 roundtrip");

  /* age secret keys are upper case */
  for (size_t i = 0; encoded[i] != '\0'; ++i) {
    char c = encoded[i];
    upper[i] = (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
    upper[i + 1] = '\0';
  }
  decoded_len = sizeof(decoded);
  CHECK(sliver_bech32_decode(upper, decoded, &decoded_len) == 0, "bech32 decode upper case");
  CHECK(decoded_len == sizeof(data) && memcmp(decoded, data, sizeof(data)) == 0,
        "bech32 upper case roundtrip");
}

static void test_age_roundtrip(void) {
  unsigned char sk[32], pk[32], base[32];
  char recipient[128], identity[160];
  const char *msg = "sliver age roundtrip";
  unsigned char *ct = NULL, *pt = NULL;
  size_t ct_len = 0, pt_len = 0;

  memset(base, 0, sizeof(base));
  base[0] = 9;
  CHECK(sliver_x25519_keypair(sk, pk) == 0, "age keypair");
  CHECK(sliver_x25519_shared(sk, base, pk) == 0, "age pub derive");

  CHECK(sliver_bech32_encode("age", pk, 32, recipient, sizeof(recipient)) == 0, "age recipient");
  CHECK(sliver_bech32_encode("AGE-SECRET-KEY-", sk, 32, identity, sizeof(identity)) == 0, "age identity");
  for (size_t i = 0; identity[i] != '\0'; ++i) {
    if (identity[i] >= 'a' && identity[i] <= 'z') {
      identity[i] = (char)(identity[i] - 'a' + 'A');
    }
  }

  CHECK(sliver_age_encrypt(recipient, msg, strlen(msg), &ct, &ct_len) == 0, "age encrypt");
  CHECK(ct != NULL && ct_len > strlen(msg), "age ciphertext size");
  {
    unsigned char tmp[32];
    size_t tl = sizeof(tmp);
    CHECK(sliver_bech32_decode(identity, tmp, &tl) == 0 && tl == 32, "identity bech32 decode");
  }
  CHECK(sliver_age_decrypt(identity, ct, ct_len, &pt, &pt_len) == 0, "age decrypt");
  CHECK(pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0, "age roundtrip mismatch");

  free(ct);
  free(pt);
}

int main(void) {
  test_sha256();
  test_blake2b();
  test_ed25519_rfc8032();
  test_x25519_rfc7748();
  test_chachapoly_roundtrip();
  test_bech32_roundtrip();
  test_age_roundtrip();

  if (g_failures != 0) {
    (void)fprintf(stderr, "%d crypto assertion(s) failed\n", g_failures);
    return 1;
  }
  (void)printf("crypto KATs ok (sha256, blake2b, ed25519, x25519, chachapoly, bech32, age)\n");
  return 0;
}
