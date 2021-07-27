/**
 * Code common to all challenger implementations (i.e., independent of
 * the TLS library).
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "challenger_helper.h"
#include "sg_stdfunc.h" // memmem()

/*
void get_quote_from_extension(uint8_t* exts, size_t exts_len, sgx_quote_t* q) {
    uint8_t report[2048];
    uint32_t report_len;
    int rc = extract_x509_extension(exts, exts_len,
                                    ias_response_body_oid, ias_oid_len,
                                    report, &report_len, sizeof(report));

    if (rc == 1) {
        get_quote_from_report(report, report_len, q);
        return;
    }

    rc = extract_x509_extension(exts, exts_len,
                                quote_oid, ias_oid_len,
                                report, &report_len, sizeof(report));
    assert(rc == 1);
    memcpy(q, report, sizeof(*q));
}
*/

/**
 * @return Returns -1 if OID not found. Otherwise, returns 1;
 */
int find_oid(const unsigned char* ext, size_t ext_len,
            const unsigned char* oid, size_t oid_len,
            unsigned char** val, size_t* len) {

    uint8_t* p = memmem(ext, ext_len, oid, oid_len);
    if (p == NULL) {
        return -1;
    }

    p += oid_len;

    int i = 0;

    // Some TLS libraries generate a BOOLEAN for the criticality of the extension.
    if (p[i] == 0x01) {
        assert(p[i++] == 0x01); // tag, 0x01 is ASN1 Boolean
        assert(p[i++] == 0x01); // length
        assert(p[i++] == 0x00); // value (0 is non-critical, non-zero is critical)
    }

    // Now comes the octet string
    assert(p[i++] == 0x04); // tag for octet string
    assert(p[i++] == 0x82); // length encoded in two bytes
    *len  =  p[i++] << 8;
    *len +=  p[i++];
    *val  = &p[i++];

    return 1;
}

/**
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
int extract_x509_extension(const uint8_t* ext, int ext_len,
                          const uint8_t* oid, size_t oid_len,
                          uint8_t* data, uint32_t* data_len, uint32_t data_max_len) {

    uint8_t* ext_data;
    size_t ext_data_len;
    
    int rc = find_oid(ext, ext_len, oid, oid_len, &ext_data, &ext_data_len);
    if (rc == -1) return -1;
    
    assert(ext_data != NULL);
    assert(ext_data_len <= data_max_len);
    memcpy(data, ext_data, ext_data_len);
    *data_len = ext_data_len;

    return 1;
}

/**
 * Extract all extensions.
 */
void extract_x509_extensions (const uint8_t* ext, int ext_len,
                              attestation_verification_report_t* attn_report) {

    extract_x509_extension(ext, ext_len,
                           ias_response_body_oid, ias_oid_len,
                           attn_report->ias_report,
                           &attn_report->ias_report_len,
                           sizeof(attn_report->ias_report));

    extract_x509_extension(ext, ext_len,
                           ias_root_cert_oid, ias_oid_len,
                           attn_report->ias_sign_ca_cert,
                           &attn_report->ias_sign_ca_cert_len,
                           sizeof(attn_report->ias_sign_ca_cert));

    extract_x509_extension(ext, ext_len,
                           ias_leaf_cert_oid, ias_oid_len,
                           attn_report->ias_sign_cert,
                           &attn_report->ias_sign_cert_len,
                           sizeof(attn_report->ias_sign_cert));

    extract_x509_extension(ext, ext_len,
                           ias_report_signature_oid, ias_oid_len,
                           attn_report->ias_report_signature,
                           &attn_report->ias_report_signature_len,
                           sizeof(attn_report->ias_report_signature));
}


/**
 * @return 1 if it is an EPID-based attestation RA-TLS
 * certificate. Otherwise, 0.
 */
int is_epid_ratls_cert (const uint8_t* der_crt, uint32_t der_crt_len) {
    uint8_t* ext_data;
    size_t ext_data_len;
    int rc;
    
    rc = find_oid(der_crt, der_crt_len,
                  ias_response_body_oid, ias_oid_len,
                  &ext_data, &ext_data_len);
    if (1 == rc) return 1;

    rc = find_oid(der_crt, der_crt_len,
                   quote_oid, ias_oid_len,
                   &ext_data, &ext_data_len);
    if (1 == rc) return 0;

    /* Something is fishy. Neither EPID nor ECDSA RA-TLC cert?! */
    assert(0);
    // Avoid compiler error: control reaches end of non-void function
    // [-Werror=return-type]
    return -1;
}
