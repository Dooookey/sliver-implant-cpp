/* src/transport/transport.c - transport vtable; the only implementation today is
 * mTLS (sliver_tls_connect), but session.c only sees this interface. */
#include "sliver/transport.h"

#include <stdlib.h>
#include <string.h>

static long mtls_read(sliver_transport_t *t, void *buf, size_t len) {
  return sliver_tls_read((sliver_tls_t *)t->state, buf, len);
}

static long mtls_write(sliver_transport_t *t, const void *buf, size_t len) {
  return sliver_tls_write((sliver_tls_t *)t->state, buf, len);
}

static void mtls_close(sliver_transport_t *t) {
  sliver_tls_close((sliver_tls_t *)t->state);
}

static const char *mtls_version(sliver_transport_t *t) {
  return sliver_tls_version((sliver_tls_t *)t->state);
}

static const char *mtls_ciphersuite(sliver_transport_t *t) {
  return sliver_tls_ciphersuite((sliver_tls_t *)t->state);
}

int sliver_transport_connect(sliver_transport_t **out, const char *host, uint16_t port,
                             const char *ca_pem, const char *cert_pem, const char *key_pem,
                             char *err, size_t err_len) {
  sliver_tls_t *tls = NULL;
  sliver_transport_t *t;

  if (out == NULL) {
    return -1;
  }
  if (sliver_tls_connect(&tls, host, port, ca_pem, cert_pem, key_pem, err, err_len) != 0) {
    return -1;
  }
  t = (sliver_transport_t *)calloc(1, sizeof(*t));
  if (t == NULL) {
    sliver_tls_close(tls);
    return -1;
  }
  t->read = mtls_read;
  t->write = mtls_write;
  t->close = mtls_close;
  t->version = mtls_version;
  t->ciphersuite = mtls_ciphersuite;
  t->state = tls;
  *out = t;
  return 0;
}

void sliver_transport_free(sliver_transport_t *t) {
  if (t == NULL) {
    return;
  }
  if (t->close != NULL) {
    t->close(t);
  }
  free(t);
}
