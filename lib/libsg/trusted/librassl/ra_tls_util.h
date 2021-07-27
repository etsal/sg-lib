#ifndef __RA_TLS_UTIL_H__
#define __RA_TLS_UTIL_H__

#include <stdint.h>

static const int rsa_3072_der_len = 1766;
static const int rsa_pub_3072_pcks_der_len = 422;
static const int rsa_pub_3072_pcks_header_len = 24;
static const int rsa_pub_3072_raw_der_len = 398; /* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */

typedef struct {
    uint8_t ias_report[2*1024];
    uint32_t ias_report_len;
    uint8_t ias_sign_ca_cert[2*1024];
    uint32_t ias_sign_ca_cert_len;
    uint8_t ias_sign_cert[2*1024];
    uint32_t ias_sign_cert_len;
    uint8_t ias_report_signature[2*1024];
    uint32_t ias_report_signature_len;
} attestation_verification_report_t;

#endif