#ifndef __ATTESTER_HELPER_H__
#define __ATTESTER_HELPER_H__

#include "sgx_report.h"

#include "ra_tls_util.h"
#include "attester.h"

void do_remote_attestation(sgx_report_data_t* report_data,
                            const ra_tls_options_t* opts,
                            attestation_verification_report_t* attn_report);

void ra_tls_create_report(sgx_report_t* report);



#endif
