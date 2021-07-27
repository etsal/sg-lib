#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <inttypes.h>

#include "sgx_eid.h"	      // sgx_enclave_id_t
#include "sgx_key_exchange.h" // sgx_ra_context
#include "sgx_quote.h"	      // sgx_spid_t

/*
 * Define a structure to be used to transfer the Attestation Status
 * from Server to client and include the Platform Info Blob in base16
 * format as Message 4.
 *
 * The structure of Message 4 is not defined by SGX: it is up to the
 * service provider, and can include more than just the attestation
 * status and platform info blob.
 */

/*
 * This doesn't have to be binary.
 */

typedef struct sp_config {
	sgx_spid_t spid;
	uint16_t quote_type;
} sp_config_t;

typedef struct _ra_msg01_struct {
	uint32_t extended_epid_group_id;
	sgx_ra_msg1_t msg1;

} ra_msg01_t;

typedef struct _ra_msg0_struct {
	uint32_t msg0_extended_epid_group_id;
} ra_msg0_t;

typedef enum {
	NotTrusted = 0,
	NotTrusted_ItsComplicated,
	Trusted_ItsComplicated,
	Trusted
} attestation_status_t;

typedef struct _ra_msg4_struct {
	attestation_status_t status;
	sgx_platform_info_t platformInfoBlob;
} ra_msg4_t;

typedef struct _msg_struct {
	uint32_t iv_len;
	uint8_t iv[12];
	sgx_aes_gcm_128bit_tag_t tag;
	uint32_t cipher_len;
	uint8_t cipher[];
} msg_t;

#include "sgx_eid.h"	       /* sgx_enclave_id_t */
#include "sgx_quote.h"	       /* sgx_spid_t */
#include "sgx_tkey_exchange.h" /* sgx_ra_context_t */

/* RA Types */
#define IAS_SUBSCRIPTION_KEY_SIZE 32

typedef struct ra_session_struct {
	sgx_ec256_private_t private_b; /* r = uint8_t [32] */
	sgx_ec256_public_t public_b;   /* gx = uint8_t [32], gy ... */
	sgx_ec256_public_t public_a;
	sgx_epid_group_id_t client_gid;	      /* uint8_t [4] */
	sgx_ec256_dh_shared_t shared_session; /* s = uint8_t[32] */
	sgx_cmac_128bit_tag_t kdk;
	sgx_cmac_128bit_key_t smk;
	sgx_cmac_128bit_key_t mk;
	sgx_cmac_128bit_key_t sk;
} ra_server_session_t;

typedef struct {
	unsigned char primary_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
	unsigned char secondary_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
	sgx_quote_sign_type_t type;
} epid_subscription;

typedef struct {
	sgx_enclave_id_t enclave_id;
	sgx_ra_context_t context;
	uint32_t extended_epid_group_id;

	sgx_spid_t spid;
	unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
	unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
	uint16_t quote_type;

	unsigned int api_ver;

	int allow_debug_enclave;
} server_ra_ctx_t;

typedef struct {
	sgx_enclave_id_t enclave_id;
	sgx_ra_context_t context;
	uint32_t extended_epid_group_id;
	int enclave_trusted;
} cli_ra_ctx_t;

#endif
