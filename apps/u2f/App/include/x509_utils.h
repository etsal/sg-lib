#ifndef __X509_UTILS_H__
#define __X509_UTILS_H__

#include "bearssl.h"
#include "x509.h"

#define ASN1_P256_SIGNATURE_SZ \
	64 + 10 // 64 for the signature output, 10 for asn1 encoding

typedef tbs_cert_details cert_details;

/* Generates self-signed X509 Certificate
 * (w.r.t. hard coded keys found in keys.h)
 *
 * @param dest
 * @param len
 * @param pub_key Subject public key for x509 cert
 * @return dest Points to malloc'd data populated with new cert
  len is populated with the length of the certexpects caller to free memory
 */
int generate_self_signed_certificate(unsigned char **dest, size_t *len,
    const br_ec_public_key *pub_key, cert_details details);

#endif