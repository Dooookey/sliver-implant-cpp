# Local mbedTLS patches

This tree is the official mbedTLS 3.6.8 release with the patches below applied.
Re-apply them when bumping the version.

## 1. Accept an empty issuer Distinguished Name (`library/x509_crt.c`)

Go's `crypto/x509` encodes an empty `pkix.Name` as a zero-length SEQUENCE.
Sliver's MTLS CA certificate is generated with an empty issuer/subject, so
`mbedtls_x509_crt_parse()` failed with
`MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA` (`rc=-0x23e0`)
and the C implant could not load the injected CA at all.

The subject path already skipped parsing when the SEQUENCE length is zero; the
issuer path now does the same:

```c
- if ((ret = mbedtls_x509_get_name(&p, p + len, &crt->issuer)) != 0) {
+ if (len && (ret = mbedtls_x509_get_name(&p, p + len, &crt->issuer)) != 0) {
```

Search for `Sliver patch` in `library/x509_crt.c` to find it.

Note: certificate verification is unaffected - a chain with empty names still
uses the DER of issuer/subject for comparison, which matches on both sides.
