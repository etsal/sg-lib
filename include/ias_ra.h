#ifndef __IAS_RA_H__
#define __IAS_RA_H__

#include <stdint.h>
#include "sgx_quote.h"
#include "ra_tls_util.h"    // attestation_verification_report_t
#include "attester.h"  // ra_tls_options
   
void obtain_attestation_verification_report(
    const sgx_quote_t* quote,
    const uint32_t quote_size,
    const ra_tls_options_t* opts,
    attestation_verification_report_t* attn_report
);


#endif
