/* sliver_mbedtls_config.h - trimmed Mbed TLS configuration for the implant.
 *
 * Start from the upstream default configuration and remove the parts the
 * implant never uses (DTLS, X.509 writing, PEM writing, self tests, error
 * strings, filesystem helpers). Size tuning continues in P5; correctness and
 * TLS 1.3 + client certificates first.
 *
 * Selected via -DMBEDTLS_CONFIG_FILE=<this file>.
 */
#ifndef SLIVER_MBEDTLS_CONFIG_H
#define SLIVER_MBEDTLS_CONFIG_H

#include "mbedtls/mbedtls_config.h"

/* --- transport surface -------------------------------------------------- */
/* TLS 1.3 is required by the Sliver server; TLS 1.2 stays enabled because the
 * 3.6 handshake code paths are shared. DTLS is not used at all. */
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID

/* The implant is a client only; keep the code paths that the library needs but
 * drop the server-only conveniences we can live without. */
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_SESSION_TICKETS

/* --- X.509 / PEM -------------------------------------------------------- */
/* Reading certificates and PEM keys is mandatory for the mTLS client; only the
 * creation/writing side is dropped. */
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_PK_WRITE_C
#undef MBEDTLS_PKCS5_C
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_PEM_WRITE_C

/* --- things a payload does not need ------------------------------------ */
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_ERROR_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_NET_C
#undef MBEDTLS_MEMORY_BUFFER_ALLOC_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_DEBUG_C

/* --- ciphers: what the Sliver protocol actually negotiates ------------- */
/* Keep AES-GCM (Go's default TLS 1.3 suites may pick AES) and
 * ChaCha20-Poly1305 (used directly for the envelope AEAD). */
#ifndef MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CHACHAPOLY_C
#endif

#endif /* SLIVER_MBEDTLS_CONFIG_H */
