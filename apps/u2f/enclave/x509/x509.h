#ifndef __X509_UTILS_H__
#define __X509_UTILS_H__

#include "BearSSL/inc/bearssl.h"
#include "x509_utils.h"
#include "common.h"

typedef struct tbs_cert_details cert_details_t;

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
    const br_ec_public_key *subject_pkey,
	const br_ec_public_key *ca_pkey,  
    const br_ec_private_key *ca_skey, 
    cert_details_t details);

#endif