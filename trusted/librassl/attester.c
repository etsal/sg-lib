#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sgx_uae_service.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include "attester.h"
#include "attester_helper.h"
#include "wolfssl_helper.h" // sha256_rsa_pubkey()
#include "sg_common.h"

//#define DEBUG_RA_ATTESTER 0

ra_tls_options_t global_opts = {
  .spid = {.id = {0xD6, 0x74, 0x09, 0x79, 0x73, 0xF8, 0x6C, 0x9A, 0x9E, 0x21, 0xC0, 0xBE, 0x25, 0x1C, 0x68, 0xD6}},
  .quote_type = SGX_LINKABLE_SIGNATURE,
  .ias_server = "api.trustedservices.intel.com/sgx/dev",
  .subscription_key = "56b5785dbf3942498a8271b7bf611f4e"
};

static void generate_x509(RsaKey* key, uint8_t* der_crt, int* der_crt_len, 
                          const attestation_verification_report_t* attn_report);

static void wolfssl_create_key_and_x509 (uint8_t* der_key, int* der_key_len, 
                                         uint8_t* der_cert, int* der_cert_len, 
                                         const ra_tls_options_t* opts);

/*
 * @param der_key
 * @param der_key_len On the way in, this is the max size for the der_key parameter. 
 *        On the way out, this is the actual size for der_key.
 * @param pem_cert
 * @param der_cert_len On the way in, this is the max size for the der_cert parameter. 
 *        On the way out, this is the actual size for der_cert.
 * @param opts
 */
void create_key_and_x509(uint8_t* der_key, int* der_key_len, 
    uint8_t* der_cert, int* der_cert_len, const ra_tls_options_t* opts) {

    wolfssl_create_key_and_x509(der_key, der_key_len, der_cert, der_cert_len, opts);
}

/* 
 * @param pem_key (out)
 * @param pem_key_len (in/out)
 * @param pem_cert (out)
 * @param pem_cert_len (in/out)
 * @para opts
 */
void create_key_and_x509_pem(uint8_t* pem_key, int* pem_key_len, 
    uint8_t* pem_cert, int* pem_cert_len,const ra_tls_options_t* opts) {
    unsigned char der_key[16 * 1024] = {0, };
    int der_key_len = sizeof(der_key);
    unsigned char der_cert[16 * 1024] = {0, };
    int der_cert_len = sizeof(der_cert_len);
    int len;

    wolfssl_create_key_and_x509(der_key, &der_key_len,
                                der_cert, &der_cert_len,
                                opts);

    len = wc_DerToPem(der_key, der_key_len, pem_key, *pem_key_len, PRIVATEKEY_TYPE);
    assert(len > 0);
    *pem_key_len = len;

    len = wc_DerToPem(der_cert, der_cert_len, pem_cert, *pem_cert_len, CERT_TYPE);
    assert(len > 0);
    *pem_cert_len = len;
}


/* Helpers */

/**
 * Caller must allocate memory for certificate.
 * 
 * @param der_crt_len On entry contains the size of der_crt buffer. 
 * On return holds actual size of certificate in bytes.
 */
void generate_x509(RsaKey* key, uint8_t* der_crt, int* der_crt_len, 
    const attestation_verification_report_t* attn_report) {
 
    Cert crt;
    wc_InitCert(&crt);

    strncpy(crt.subject.country, "CA", CTC_NAME_SIZE);
    strncpy(crt.subject.state, "ON", CTC_NAME_SIZE);
    strncpy(crt.subject.locality, "Waterloo", CTC_NAME_SIZE);
    strncpy(crt.subject.org, "University of Waterloo", CTC_NAME_SIZE);
    strncpy(crt.subject.unit, "RCS", CTC_NAME_SIZE);
    strncpy(crt.subject.commonName, "rcs", CTC_NAME_SIZE);
    //strncpy(crt.subject.email, "webmaster@intel.com", CTC_NAME_SIZE);

    memcpy(crt.iasAttestationReport, attn_report->ias_report,
           attn_report->ias_report_len);
    crt.iasAttestationReportSz = attn_report->ias_report_len;

    memcpy(crt.iasSigCACert, attn_report->ias_sign_ca_cert,
           attn_report->ias_sign_ca_cert_len);
    crt.iasSigCACertSz = attn_report->ias_sign_ca_cert_len;

    memcpy(crt.iasSigCert, attn_report->ias_sign_cert,
           attn_report->ias_sign_cert_len);
    crt.iasSigCertSz = attn_report->ias_sign_cert_len;

    memcpy(crt.iasSig, attn_report->ias_report_signature,
           attn_report->ias_report_signature_len);
    crt.iasSigSz = attn_report->ias_report_signature_len;

    RNG    rng;
    wc_InitRng(&rng);
    
    int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
    assert(certSz > 0);
    *der_crt_len = certSz;

}

void wolfssl_create_key_and_x509 (uint8_t* der_key, int* der_key_len, 
    uint8_t* der_cert, int* der_cert_len, const ra_tls_options_t* opts) {

    RsaKey genKey;
    RNG    rng;
    int    ret;

    sgx_report_data_t report_data = {0, };
    attestation_verification_report_t attestation_report;

    // Generate RSA key with exponent e=65537, len=3072(bits)
    wc_InitRng(&rng);
    wc_InitRsaKey(&genKey, 0);
    ret = wc_MakeRsaKey(&genKey, 3072, 65537, &rng);
    assert(ret == 0);
    
    uint8_t der[4096];
    int  derSz = wc_RsaKeyToDer(&genKey, der, sizeof(der));

    assert(derSz >= 0);
    assert(derSz <= (int) *der_key_len);

    *der_key_len = derSz;
    memcpy(der_key, der, derSz);

    // Prepare report data (hash of whatever data we want to add, 
    //  in this case its a key)
    sha256_rsa_pubkey(report_data.d, &genKey);    

    // Create report and send it to IAS 
    do_remote_attestation(&report_data, opts, &attestation_report);

    // Create a cert (with the IAS response appended to the cert)
    generate_x509(&genKey, der_cert, der_cert_len, &attestation_report);

#ifdef DEBUG_RA_ATTESTER
    edividerWithText("Self Signed Cert");
    eprintf("+++ plug into asn1 decoder: https://lapo.it/asn1js/#\n");
    eprintf("%s \n", hexstring(der_cert, *der_cert_len));
    edivider();
#endif
    
}

/*
time_t XTIME(time_t* tloc) {
    //time_t x = 1512498557; // Dec 5, 2017, 10:29 PDT
     time_t x = 1615171370; // March 8th 2021
    if (tloc) *tloc = x;
    return x;
}

time_t mktime(struct tm* tm) {
    (void) tm;
    assert(0);
    return (time_t) 0;
}
*/
