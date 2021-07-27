#include <assert.h>
#include <stdlib.h>

#include "attester.h" // ra_tls_options
#include "ias_ra.h"
#include "ra_tls_util.h" // attestation_verification_report_t
#include "sg_common.h"
#include "sg_u.h"
#include "sgx_report.h" // sgx_target_info_t, sgx_report_t
#include "sgx_uae_service.h"
/* Untrusted code to do remote attestation with the SGX SDK */

void
ocall_sgx_init_quote(sgx_target_info_t *target_info)
{
	sgx_epid_group_id_t gid;
	sgx_status_t status = sgx_init_quote(target_info, &gid);
	assert(status == SGX_SUCCESS);
}

void
ocall_remote_attestation(sgx_report_t *report, const ra_tls_options_t *opts,
    attestation_verification_report_t *attn_report)
{

	// Produce quote
	uint32_t quote_size;
	sgx_calc_quote_size(NULL, 0, &quote_size);

	sgx_quote_t *quote = (sgx_quote_t *)calloc(1, quote_size);

	sgx_status_t status;
	status = sgx_get_quote(report, opts->quote_type, &opts->spid, NULL,
	    NULL, 0, NULL, quote, quote_size);
	assert(SGX_SUCCESS == status);

#ifdef UNTRUSTED_ATTEST
	eprintf("\t\t+ %s : quote details\n", __FUNCTION__);
	print_quote_details(quote, 1);
#endif

	// Verify against IAS
	obtain_attestation_verification_report(
	    quote, quote_size, opts, attn_report);
}
