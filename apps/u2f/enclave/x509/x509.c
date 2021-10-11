#include <stdlib.h>
#include <assert.h>

#include "x509.h"
#include "stdfunc.h"

/* Generates self-signed X509 Certificate
 * (w.r.t. hard coded keys found in keys.h)
 *
 * @param dest
 * @param len
 * @param pub_key Subject public key for x509 cert
 * @param priv_key Key to sign the cert with
 * @return dest Points to malloc'd data populated with new cert
  len is populated with the length of the certexpects caller to free memory
 */
int
generate_self_signed_certificate(unsigned char **dest, size_t *len,
    const br_ec_public_key *subject_pkey,
	const br_ec_public_key *ca_pkey,  
    const br_ec_private_key *ca_skey, 
    cert_details_t details)
{
	unsigned char *tbs_cert, *cert;
	size_t tbs_cert_len, cert_len;

	br_sha256_context hash_ctx;
	unsigned char hashed_tbs_cert[br_sha256_SIZE] = { 0 };

	size_t signed_tbs_cert_len;
	unsigned char signed_tbs_cert[ASN1_P256_SIGNATURE_SZ + 10] = { 0 };

	assert(ca_pkey->curve == BR_EC_secp256r1);
	assert(ca_skey->curve == BR_EC_secp256r1);

	/* Generate the TBSCertificate (first part of the X509 certificate) */
	tbs_cert_len = generate_tbs_certificate(NULL, 
		(const unsigned char *)subject_pkey->q, subject_pkey->qlen, 
		(const unsigned char *)ca_pkey->q, ca_pkey->qlen, 
		details);

	tbs_cert = (unsigned char *)malloc(tbs_cert_len);
	tbs_cert_len = generate_tbs_certificate(tbs_cert, 
		(const unsigned char *)subject_pkey->q, subject_pkey->qlen, 
		(const unsigned char *)ca_pkey->q, ca_pkey->qlen, 
		details);

	/* Hash the TBSCertificate */
	br_sha256_init(&hash_ctx);
	br_sha256_update(&hash_ctx, tbs_cert, tbs_cert_len);
	br_sha256_out(&hash_ctx, hashed_tbs_cert);

	/* Sign the hashed TBSCertificate */
	signed_tbs_cert_len = br_ecdsa_i31_sign_asn1(&br_ec_all_m31,
	    &br_sha256_vtable, hashed_tbs_cert,
	    ca_skey, signed_tbs_cert);

	if (signed_tbs_cert == 0) {
#if DEBUG_X509
		printf("Error, br_ecdsa_i31_sign_asn1 failed");
#endif
		free(tbs_cert);
		return 1;
	}

	/* Generate X509 certificate */
	cert_len = generate_final_certificate(
	    NULL, tbs_cert, tbs_cert_len, signed_tbs_cert, signed_tbs_cert_len);
	cert = (unsigned char *)malloc(cert_len);
	generate_final_certificate(
	    cert, tbs_cert, tbs_cert_len, signed_tbs_cert, signed_tbs_cert_len);

#if DEBUG_X509
	eprintf("TBSCertificate  [len %d]\n", tbs_cert_len);
	print_bytes(tbs_cert, tbs_cert_len);
	eprintf("\n\nSigned Certificate [%d]\n", signed_tbs_cert_len);
	print_bytes(signed_tbs_cert, signed_tbs_cert_len);
	eprintf("\n\nX509 Certificate [len %d]\n", cert_len);
	print_bytes(cert, cert_len);
	eprintf("\n\n");
#endif

	free(tbs_cert);

	*dest = cert;
	*len = cert_len;

	return 0;
}
