#include <assert.h>
#include <string.h>

#include "sgx_utils.h"  // sgx_create_report()

#include "sg_t.h"       // Boundary calls
#include "attester.h"

/* Trusted portion (called from within the enclave) to do remote
   attestation with the SGX SDK.  */

/*
 * @param report_data 64 bytes provided by the user to signed by QE
 * @param opts ra options (spid ...etc.)
 * @param att_report filled for caller
 */
void do_remote_attestation(sgx_report_data_t* report_data,
    const ra_tls_options_t* opts,
    attestation_verification_report_t* attn_report) {

    sgx_target_info_t target_info = {0, };
    ocall_sgx_init_quote(&target_info);

    sgx_report_t report = {0, };
    sgx_status_t status = sgx_create_report(&target_info, report_data, &report); // EREPORT
    assert(status == SGX_SUCCESS);

    ocall_remote_attestation(&report, opts, attn_report);
}

void ra_tls_create_report(sgx_report_t* report) {
    sgx_target_info_t target_info = {0, };
    sgx_report_data_t report_data = {0, };
    memset(report, 0, sizeof(*report));

    sgx_create_report(&target_info, &report_data, report);
}
