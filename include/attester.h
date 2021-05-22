#ifndef _RA_ATTESTER_H_
#define _RA_ATTESTER_H_
#include <stdint.h>

#include "sgx_quote.h"

typedef struct something {
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;
    /* NULL-terminated string of domain name/IP, port and path prefix,
       e.g., api.trustedservices.intel.com/sgx/dev for development and
       api.trustedservices.intel.com/sgx for production. */
    const char ias_server[512];
    const char subscription_key[32];
} ra_tls_options_t;

/*
sgx_spid_t global_spid = { .id = {0xD6, 0x74, 0x09, 0x79, 0x73, 0xF8, 0x6C, 0x9A, 
                                  0x9E, 0x21, 0xC0, 0xBE, 0x25, 0x1C, 0x68, 0xD6}
};
*/

void create_key_and_x509(uint8_t* der_key, int* der_key_len, 
	                       uint8_t* der_cert, int* der_cert_len, 
                         const ra_tls_options_t* opts);

void create_key_and_x509_pem(uint8_t* pem_key, int* pem_key_len, 
	                           uint8_t* pem_cert, int* pem_cert_len, 
                             const ra_tls_options_t* opts);

void ra_tls_create_report(sgx_report_t* report);

#endif

