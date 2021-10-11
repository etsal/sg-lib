#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "x509_utils.h"
#include "BearSSL/inc/bearssl.h"
//#include "keys.h"
#include "stdfunc.h"


static void
print_hex(unsigned char *buf, size_t len)
{
	for (int i = 0; i < len; ++i)
		eprintf("%02x", buf[i]);
	eprintf("");
}

// Root CA public key
extern unsigned char root_ca_public_key_arr[];

static const unsigned char OID_ecdsaWithSHA256[] = { 0x08, 0x2A, 0x86, 0x48,
	0xCE, 0x3D, 0x04, 0x03, 0x02 }; // first byte is len

static const unsigned char OID_ecPublicKey[] = { 0x07, 0x2A, 0x86, 0x48, 0xCE,
	0x3D, 0x02, 0x01 };

static const unsigned char OID_secp256r1[] = { 0x08, 0x2A, 0x86, 0x48, 0xCE,
	0x3D, 0x03, 0x01, 0x07 };

/*
static const unsigned char OID_secp384r1[] = {
	0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
};
*/

static const unsigned char OID_curveX25519[] = { 0x03, 0x2B, 0x65, 0x6E };

static const unsigned char OID_curveEd25519[] = { 0x03, 0x2B, 0x65, 0x70 };

static const unsigned char OID_countryName[] = { 0x03, 0x55, 0x04,
	0x06 }; // first byte is len

static const unsigned char OID_organizationName[] = { 0x03, 0x55, 0x04,
	0x0A }; // first byte is len

static const unsigned char OID_commonName[] = { 0x03, 0x55, 0x04,
	0x03 }; // first byte is len

static const unsigned char OID_keyUsage[] = { 0x03, 0x55, 0x1D, 0x0F };

static const unsigned char OID_basicConstraints[] = { 0x03, 0x55, 0x1D, 0x13 };

static const unsigned char OID_authorityKeyIdentifier[] = { 0x03, 0x55, 0x1D,
	0x23 };

static const unsigned char OID_subjectAltName[] = { 0x03, 0x55, 0x1D, 0x11 };

static size_t
asn1_encode_length(unsigned char *dest, size_t len)
{
	unsigned char *buf;
	size_t z;
	int i, j;

	buf = dest;
	if (len < 0x80) {
		if (buf != NULL) {
			*buf = len;
		}
		return 1;
	}
	i = 0;
	for (z = len; z != 0; z >>= 8) {
		i++;
	}
	if (buf != NULL) {
		*buf++ = 0x80 + i;
		for (j = i - 1; j >= 0; j--) {
			*buf++ = len >> (j << 3);
		}
	}
	return i + 1;
}

static size_t
len_of_len(size_t len)
{
	return asn1_encode_length(NULL, len);
}

static size_t
generate_version(unsigned char *buf)
{
	unsigned char version[] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
	size_t version_len = sizeof version;

#if DEBUG_X509
	eprintf("Version length %d\n", version_len);
#endif

	if (buf != NULL) {
		memcpy(buf, version, version_len);
	}

	return version_len;
}

static size_t
generate_serialNumber(unsigned char *buf)
{
	// unsigned char serialNumber[] = {0x02, 0x14, 0x1C, 0x4D, 0x00, 0x91,
	// 0x69, 0xE2, 0x46, 0xAC, 0x90, 0x7C, 0x64, 0x5C, 0x53, 0xF1, 0xFF,
	// 0xB7, 0xC1, 0xCB, 0x6E, 0x7A};
	unsigned char serialNumber[] = { 0x02, 0x14, 0x7F, 0x53, 0x0B, 0x50,
		0x00, 0xE0, 0x4D, 0xF2, 0xD0, 0x5F, 0x94, 0x7B, 0xAE, 0xA0,
		0x12, 0x42, 0x47, 0xCC, 0xEA, 0x30 };

	size_t serialNumber_len = sizeof serialNumber;

#if DEBUG_X509
	eprintf("Serial Number length %d\n", serialNumber_len);
#endif

	if (buf != NULL) {
		memcpy(buf, serialNumber, serialNumber_len);
	}

	return serialNumber_len;
}

static size_t
generate_signature(unsigned char *buf)
{
	size_t signature_len, len_oid;
	size_t lenlen;

	len_oid = 2 + OID_ecdsaWithSHA256[0];
	signature_len = 2 + len_oid;

#if DEBUG_X509
	eprintf("Signature length %d\n", signature_len);
#endif

	if (buf != NULL) {
		*buf++ = 0x30;
		lenlen = asn1_encode_length(buf, len_oid);
		buf += lenlen;

		*buf++ = 0x06;
		memcpy(buf, OID_ecdsaWithSHA256, OID_ecdsaWithSHA256[0] + 1);
		buf += OID_ecdsaWithSHA256[0] + 1;
	}

	return signature_len;
}

static size_t
generate_validity(unsigned char *buf, char *notBefore, char *notAfter)
{
	size_t validity_len, group_len, notBefore_len, notAfter_len;
	size_t utc_data_len = 13;

	notBefore_len = 2 + utc_data_len;
	notAfter_len = 2 + utc_data_len;
	group_len = notBefore_len + notAfter_len;
	validity_len = 1 + len_of_len(group_len) + group_len;

	if (buf != NULL) {
		*buf++ = 0x30;
		buf += asn1_encode_length(buf, group_len);

		*buf++ = 0x17;
		*buf++ = 0x0D; // UTC time will always be 13 bytes in length

		for (int i = 0; i < utc_data_len; ++i)
			*buf++ = notBefore[i];

		*buf++ = 0x17;
		*buf++ = 0x0D; // UTC time will always be 13 bytes in length

		for (int i = 0; i < utc_data_len; ++i)
			*buf++ = notAfter[i];
	}

#if DEBUG_X509
	eprintf("Validity length %d\n", validity_len);
#endif

	return validity_len;
}

static size_t
generate_subject(unsigned char *buf, char *commonName, char *organizationName,
    char *countryName)
{
	size_t ps_len, oid_len, seq_len, sets_len = 0;
	size_t subject_len, commonName_len, organizationName_len,
	    countryName_len = 0;

	int set_flag = 0;

	do {
		if (set_flag) {
			*buf++ = 0x30;
			buf += asn1_encode_length(buf, sets_len);
		}

		ps_len = 2 + strlen(countryName); // PrintableString tag
		oid_len = 2 + OID_countryName[0]; // OID tag
		seq_len = 2 + ps_len + oid_len;	  // SEQUENCE tag
		sets_len = 2 + seq_len;

		if (set_flag) {
			*buf++ = 0x31;
			buf += asn1_encode_length(buf, seq_len);

			*buf++ = 0x30;
			buf += asn1_encode_length(buf, oid_len + ps_len);

			*buf++ = 0x06;
			memcpy(buf, OID_countryName, OID_countryName[0] + 1);
			buf += OID_countryName[0] + 1;

			*buf++ = 0x13;
			*buf++ = strlen(countryName);
			for (int i = 0; i < strlen(countryName); ++i)
				*buf++ = countryName[i];
		}

		ps_len = 2 + strlen(organizationName); // PrintableString tag
		oid_len = 2 + OID_organizationName[0]; // OID tag
		seq_len = 2 + ps_len + oid_len;	       // SEQUENCE tag
		sets_len += 2 + seq_len;

		if (set_flag) {
			*buf++ = 0x31;
			buf += asn1_encode_length(buf, seq_len);

			*buf++ = 0x30;
			buf += asn1_encode_length(buf, oid_len + ps_len);

			*buf++ = 0x06;
			memcpy(buf, OID_organizationName,
			    OID_organizationName[0] + 1);
			buf += OID_organizationName[0] + 1;

			*buf++ = 0x13;
			*buf++ = strlen(organizationName);
			for (int i = 0; i < strlen(organizationName); ++i)
				*buf++ = organizationName[i];
		}

		ps_len = 2 + strlen(commonName); // PrintableString tag
		oid_len = 2 + OID_commonName[0]; // OID tag
		seq_len = 2 + ps_len + oid_len;	 // SEQUENCE tag
		sets_len += 2 + seq_len;

		if (set_flag) {
			*buf++ = 0x31;
			buf += asn1_encode_length(buf, seq_len);

			*buf++ = 0x30;
			buf += asn1_encode_length(buf, oid_len + ps_len);

			*buf++ = 0x06;
			memcpy(buf, OID_commonName, OID_commonName[0] + 1);
			buf += OID_commonName[0] + 1;

			*buf++ = 0x13;
			*buf++ = strlen(commonName);
			for (int i = 0; i < strlen(commonName); ++i)
				*buf++ = commonName[i];
		}

		subject_len = 1 + len_of_len(sets_len) + sets_len; // SET tag

		if (set_flag == 0 && buf != NULL) {
			set_flag = 1;
		} else if (set_flag == 1) {
			set_flag = 0;
		}

	} while (set_flag == 1);

#if DEBUG_X509
	eprintf("Subject length %d\n", subject_len);
#endif

	return subject_len;
}

static size_t
generate_subjectPublicKeyInfo(
    unsigned char *buf, const unsigned char *pub_key, size_t pub_key_len)
{
	size_t subjectpki_len, group_len, seq_len, oid_group_len,
	    bit_string_len;

	oid_group_len = 2 + OID_ecPublicKey[0]; // OID tag
	oid_group_len += 2 + OID_secp256r1[0];	// OID tag
	seq_len = 2 + oid_group_len;

	bit_string_len = 1 + len_of_len(pub_key_len + 1) + pub_key_len +
	    1; // BIT STRING requires extra 0x00

	group_len = seq_len + bit_string_len;

	subjectpki_len = 1 + len_of_len(group_len) + group_len;

	if (buf != NULL) {
		*buf++ = 0x30;
		buf += asn1_encode_length(buf, group_len);

		*buf++ = 0x30;
		buf += asn1_encode_length(buf, oid_group_len);

		*buf++ = 0x06;
		memcpy(buf, OID_ecPublicKey, OID_ecPublicKey[0] + 1);
		buf += OID_ecPublicKey[0] + 1;

		*buf++ = 0x06;
		memcpy(buf, OID_secp256r1, OID_secp256r1[0] + 1);
		buf += OID_secp256r1[0] + 1;

		*buf++ = 0x03;
		buf += asn1_encode_length(buf, pub_key_len + 1);
		*buf++ = 0x00;
		memcpy(buf, pub_key, pub_key_len);
		buf += pub_key_len;
	}

#if DEBUG_X509
	eprintf("Subject Public Key Info length %d\n", subjectpki_len);
#endif

	return subjectpki_len;
}

/*
 * SEQUENCE (2 elem)
 * OBJECT IDENTIFIER 2.5.29.35 authorityKeyIdentifier (X.509 extension)
 * OCTET STRING (1 elem)
 *   SEQUENCE (1 elem)
 *     [0] (20 byte) F8EF7FF2CD7867A8DE6F8F248D88F1870302B3EB
 */
static size_t
generate_authorityKeyIdentifier(unsigned char *buf)
{

	unsigned char authorityKeyIdentifier[] = { 0x30, 0x1F, 0x06, 0x03, 0x55,
		0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x44, 0xF6,
		0xF4, 0xF0, 0xCB, 0xA3, 0x12, 0xAE, 0x80, 0xB3, 0xB7, 0x4F,
		0x7B, 0x99, 0x6A, 0x74, 0x1E, 0x68, 0xA7, 0xA2 };

	size_t authorityKeyIdentifier_len = sizeof authorityKeyIdentifier;

	if (buf != NULL) {
		memcpy(buf, authorityKeyIdentifier, authorityKeyIdentifier_len);
		buf += authorityKeyIdentifier_len;
	}

	return authorityKeyIdentifier_len;

	/*
	size_t authorityKeyIdentifier_len;
	size_t keyIdentifier_len, seq_len, octet_len, oid_len;

	keyIdentifier_len = 1 + len_of_len(key_id_len) + key_id_len;
	seq_len = 1 + len_of_len(keyIdentifier_len) + keyIdentifier_len;
	octet_len = 1 + len_of_len(seq_len) + seq_len;
	oid_len = 2 + OID_authorityKeyIdentifier[0];

	authorityKeyIdentifier_len = 1 + len_of_len(oid_len + octet_len) +
	oid_len + octet_len;

	if (buf != NULL) {
		*buf ++ = 0x30; // SEQUENCE tag
		buf += asn1_encode_length(buf, oid_len + octet_len);

		*buf ++ = 0x06; // OID tag
		memcpy(buf, OID_authorityKeyIdentifier,
	OID_authorityKeyIdentifier[0]+1); buf +=
	OID_authorityKeyIdentifier[0]+1;

		*buf ++ = 0x04; // OCTET STRING tag
		buf += asn1_encode_length(buf, seq_len);

		*buf ++ = 0x30; // SEQUENCE tag
		buf += asn1_encode_length(buf, keyIdentifier_len);

		*buf ++ = 0x80; //[0] tag
		buf += asn1_encode_length(buf, key_id_len);
		memcpy(buf, key_id, key_id_len);
		buf += key_id_len;

	}

	return authorityKeyIdentifier_len;
	*/
}

/*
SEQUENCE (2 elem)
	  OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
	  OCTET STRING (1 elem)
	    SEQUENCE (0 elem)
*/
static size_t
generate_basicConstraints(unsigned char *buf)
{
	unsigned char basicConstraints[] = { 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D,
		0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00 };

	size_t basicConstraints_len = sizeof basicConstraints;

	if (buf != NULL) {
		memcpy(buf, basicConstraints, basicConstraints_len);
		buf += basicConstraints_len;
	}

	return basicConstraints_len;
}

static size_t
generate_keyUsage(unsigned char *buf)
{
	unsigned char keyUsage[] = { 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F,
		0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x00, 0x86 };

	size_t keyUsage_len = sizeof keyUsage;

	if (buf != NULL) {
		memcpy(buf, keyUsage, keyUsage_len);
		buf += keyUsage_len;
	}

	return keyUsage_len;
}

static size_t
generate_subjectAltName(unsigned char *buf)
{

	unsigned char subjectAltName[] = { 0x30, 0x14, 0x06, 0x03, 0x55, 0x1D,
		0x11, 0x04, 0x0D, 0x30, 0x0B, 0x82, 0x09, 0x6C, 0x6F, 0x63,
		0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74 };

	/*
		unsigned char subjectAltName[] = {
			0x30, 0x14, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04,
			0x0D, 0x30, 0x0B, 0x82, 0x04, 0x73, 0x74, 0x65, 0x66
		};
		*/

	size_t subjectAltName_len = sizeof subjectAltName;

	if (buf != NULL) {
		memcpy(buf, subjectAltName, subjectAltName_len);
		buf += subjectAltName_len;
	}

	return subjectAltName_len;
}

/* WARNING: sketchy */
static size_t
generate_subjectKeyIdentifier(
    unsigned char *buf, const unsigned char *pub_key, size_t pub_key_len)
{
	unsigned char subjectKeyIdentifier[] = { 0x30, 0x1D, 0x06, 0x03, 0x55,
		0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14 };
	size_t subjectKeyIdentifier_len;

	subjectKeyIdentifier_len = subjectKeyIdentifier[1] + 2;

	if (buf != NULL) {
		unsigned char sha_key[br_sha1_SIZE];
		br_sha1_context sha_ctx;

		br_sha1_init(&sha_ctx);
		br_sha1_update(&sha_ctx, pub_key, pub_key_len);
		br_sha1_out(&sha_ctx, sha_key);

		memcpy(buf, subjectKeyIdentifier, sizeof subjectKeyIdentifier);
		buf += sizeof subjectKeyIdentifier;

		memcpy(buf, sha_key, br_sha1_SIZE);
		buf += br_sha1_SIZE;
	}

	return subjectKeyIdentifier_len;
}

static size_t
generate_extensions(unsigned char *buf, const unsigned char *subject_pubkey,
    size_t subject_pubkey_len)
{

	size_t extensions_len, group_len, seq_len, authorityKeyIdentifier_len,
	    basicConstaints_len, keyUsage_len, subjectAltName_len,
	    subjectKeyIdentifier_len;

	authorityKeyIdentifier_len = generate_authorityKeyIdentifier(NULL);
	subjectKeyIdentifier_len = generate_subjectKeyIdentifier(
	    NULL, subject_pubkey, subject_pubkey_len);
	basicConstaints_len = generate_basicConstraints(NULL);
	keyUsage_len = 0; // generate_keyUsage(NULL);
	subjectAltName_len = generate_subjectAltName(NULL);

	group_len = authorityKeyIdentifier_len + basicConstaints_len +
	    keyUsage_len + subjectAltName_len + subjectKeyIdentifier_len;

	seq_len = 1 + len_of_len(group_len) + group_len;
	extensions_len = 1 + len_of_len(seq_len) + seq_len;

	if (buf != NULL) {

		*buf++ = 0xA3; // [3] tag
		buf += asn1_encode_length(buf, seq_len);

		*buf++ = 0x30; // SEQUENCE tag
		buf += asn1_encode_length(buf, group_len);

		buf += generate_authorityKeyIdentifier(buf);
		buf += generate_subjectKeyIdentifier(
		    buf, subject_pubkey, subject_pubkey_len);
		buf += generate_basicConstraints(buf);
		buf += 0; // generate_keyUsage(buf);
		buf += generate_subjectAltName(buf);
	}

#if DEBUG_X509
	eprintf("Extensions length %d\n", extensions_len);
#endif

	return extensions_len;
}

size_t 
generate_tbs_certificate(unsigned char *dest,
    const unsigned char *subject_pubkey, size_t subject_pubkey_len,
    const unsigned char *ca_pubkey, size_t ca_pubkey_len,
    struct tbs_cert_details details)
{
	unsigned char *buf = dest;
	size_t len, len_version, len_serialNumber, len_signature, len_issuer,
	    len_validity, len_subject, len_subjectpki, len_seq, len_extensions;

	const unsigned char *authorityKeyIdentifier = ca_pubkey;//root_ca_public_key_arr;
	size_t authorityKeyIdentifier_len = 97;

	assert(ca_pubkey_len == 65); //p256 curve

	len_version = generate_version(NULL);
	len_serialNumber = generate_serialNumber(NULL);
	len_signature = generate_signature(NULL);
	len_issuer = generate_subject(
	    NULL, "rcs", "RCS", "CA"); // TODO: Subject and issuer have the same
				       // structure, fix this to be one function
	len_validity = generate_validity(
	    NULL, details.not_before, details.not_after);
	len_subject = generate_subject(NULL, details.subj_common_name,
	    details.subj_org_name, details.subj_cntry_name);
	len_subjectpki = generate_subjectPublicKeyInfo(
	    NULL, subject_pubkey, subject_pubkey_len);
	len_extensions = generate_extensions(
	    NULL, subject_pubkey, subject_pubkey_len);

	len_seq = len_version + len_serialNumber + len_signature + len_issuer +
	    len_validity + len_subject + len_subjectpki + len_extensions;
	len = 1 + len_of_len(len_seq) + len_seq;

	if (buf == NULL) {
		return len;
	}

	unsigned char *buf_start = buf;

	*buf++ = 0x30;
	buf += asn1_encode_length(buf, len_seq);
	buf += generate_version(buf);
	buf += generate_serialNumber(buf);
	buf += generate_signature(buf);
	buf += generate_subject(buf, "rcs", "RCS", "CA");
	buf += generate_validity(buf, details.not_before, details.not_after);
	buf += generate_subject(buf, details.subj_common_name,
	    details.subj_org_name, details.subj_cntry_name);
	buf += generate_subjectPublicKeyInfo(
	    buf, subject_pubkey, subject_pubkey_len);
	buf += generate_extensions(buf, subject_pubkey, subject_pubkey_len);

	buf -= len;

	return len;
}

static size_t
generate_signatureAlgorithm(unsigned char *buf)
{
	size_t signatureAlgorithm_len, oid_len;

	oid_len = 2 + OID_ecdsaWithSHA256[0];
	signatureAlgorithm_len = 2 + oid_len;

	if (buf != NULL) {
		*buf++ = 0x30;
		buf += asn1_encode_length(buf, oid_len);
		*buf++ = 0x06;
		memcpy(buf, OID_ecdsaWithSHA256, OID_ecdsaWithSHA256[0] + 1);
		buf += OID_ecdsaWithSHA256[0] + 1;
	}

#if DEBUG_X509
	eprintf("signatureAlgorithm_len %d\n", signatureAlgorithm_len);
#endif
	return signatureAlgorithm_len;
}

// Expects signed_tbs_cert to be in asn1 format
size_t
generate_final_certificate(unsigned char *dest, unsigned char *tbs_cert,
    size_t tbs_cert_len, unsigned char *signed_tbs_cert,
    size_t signed_tbs_cert_len)
{
	unsigned char *buf = dest;
	size_t len, signatureAlgorithm_len, signatureValue_len, group_len;

	signatureAlgorithm_len = generate_signatureAlgorithm(NULL);
	signatureValue_len = 1 + len_of_len(signed_tbs_cert_len + 1) +
	    signed_tbs_cert_len + 1;

	group_len = tbs_cert_len + signatureAlgorithm_len + signatureValue_len;

	len = 1 + len_of_len(group_len) + group_len;

	if (buf != NULL) {

		*buf++ = 0x30;
		buf += asn1_encode_length(buf, group_len);

		memcpy(buf, tbs_cert, tbs_cert_len);
		buf += tbs_cert_len;

		buf += generate_signatureAlgorithm(buf);

		*buf++ = 0x03;
		buf += asn1_encode_length(buf, signed_tbs_cert_len + 1);
		*buf++ = 0x00;

		memcpy(buf, signed_tbs_cert, signed_tbs_cert_len);
		buf += signed_tbs_cert_len;

		buf -= len;
	}

	return len;
}
