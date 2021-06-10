/**
 * wolfSSL-based implementation of the RA-TLS challenger API
 * (cf. ra-challenger.h).
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/signature.h>

#include "challenger.h"
#include "challenger_helper.h"

#include "wolfssl_helper.h" // sha256_rsa_pubkey()
#include "sg_common.h"
#include "base64.h"

//#define DEBUG_CHALLENGER 1

extern unsigned char ias_sign_ca_cert_der[];
extern unsigned int ias_sign_ca_cert_der_len;

static void get_quote_from_extension(const uint8_t* exts, size_t exts_len, sgx_quote_t* q);
static int epid_verify_sgx_cert_extensions(uint8_t* der_crt, uint32_t der_crt_len);
static int verify_enclave_quote_status(const char* ias_report, int ias_report_len);
static int verify_ias_certificate_chain(attestation_verification_report_t* attn_report);
static int verify_ias_report_signature(attestation_verification_report_t* attn_report);
static int verify_report_data_against_server_cert(DecodedCert* crt, sgx_quote_t* quote);

//
void get_quote_from_cert(const uint8_t* der_crt, uint32_t der_crt_len, sgx_quote_t* q) {
    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, (byte*) der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);
   
    get_quote_from_extension(crt.extensions, crt.extensionsSz, q);

#ifdef DEBUG_CHALLENGER
    print_quote_details(q, 0);
#endif

    FreeDecodedCert(&crt);
}

// helper
void get_quote_from_extension(const uint8_t* exts, size_t exts_len, sgx_quote_t* q) {
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

//
void get_quote_from_report(const uint8_t* report /* in */, 
    const int report_len  /* in */, sgx_quote_t* quote) {
    // Move report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[report_len + 1];
    memcpy(buf, report, report_len);
    buf[report_len] = '\0';

    const char* json_string = "\"isvEnclaveQuoteBody\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);
    const char* p_end = strchr(p_begin, '"');
    assert(p_end != NULL);

    const int quote_base64_len = p_end - p_begin;
    uint8_t* quote_bin = malloc(quote_base64_len);
    uint32_t quote_bin_len = quote_base64_len;

/*
    Base64_Decode((const byte*) p_begin, quote_base64_len,
                  quote_bin, &quote_bin_len);              
*/  
    base64_decode_wbuf(p_begin, quote_base64_len, quote_bin, (size_t *)&quote_bin_len);  

    #if DEBUG_CHALLENGER
    edividerWithText("Quote Decoded");
    eprintf("%s\n", hexstring(quote_bin, quote_bin_len));
    edivider();
    //print_quote_details((sgx_quote_t*)quote_bin, 0);
    #endif

    assert(quote_bin_len <= sizeof(sgx_quote_t));
    memset(quote, 0, sizeof(sgx_quote_t));
    memcpy(quote, quote_bin, quote_bin_len);
    free(quote_bin);
}

//
int verify_sgx_cert_extensions(uint8_t* der_crt, uint32_t der_crt_len) {

    assert(is_epid_ratls_cert(der_crt, der_crt_len));
    return epid_verify_sgx_cert_extensions(der_crt, der_crt_len);
}

/* Helpers */

int verify_report_data_against_server_cert(DecodedCert* crt, sgx_quote_t* quote) {
    /* crt->publicKey seems to be the DER encoded public key. The
       OpenSSL DER formatted version of the public key obtained with
       openssl rsa -in ./server-key.pem -pubout -outform DER -out
       server-pubkey.der has an additional 24 bytes
       prefix/header. d->pubKeySize is 270 and the server-pubkey.der
       file has 294 bytes. That's to be expected according to [1] */
    /* [1] https://crypto.stackexchange.com/questions/14491/why-is-a-2048-bit-public-rsa-key-represented-by-540-hexadecimal-characters-in  */
    
    /* 2017-12-06, Thomas Knauth, A hard-coded offset into the
       DER-encoded public key only works for specific key sizes. The
       24 byte offset is specific to 2048 bit RSA keys. For example, a
       1024 bit RSA key only has an offset of 22.
 */
    RsaKey rsaKey;
    unsigned int idx = 0;
    int ret;
    
    wc_InitRsaKey(&rsaKey, NULL);
    ret = wc_RsaPublicKeyDecode(crt->publicKey, &idx, &rsaKey, crt->pubKeySize);
    assert(ret == 0);
    
    byte shaSum[SHA256_DIGEST_SIZE] = {0, };
    sha256_rsa_pubkey(shaSum, &rsaKey);
    wc_FreeRsaKey(&rsaKey);

#ifdef DEBUG_CHALLENGER
    eprintf("SHA256 of server's public key: %s\n", hexstring(shaSum, SHA256_DIGEST_SIZE));
    eprintf("Quote's report data: %s\n", hexstring(quote->report_body.report_data.d, SGX_REPORT_DATA_SIZE));
#endif
    
    assert(SHA256_DIGEST_SIZE <= SGX_REPORT_DATA_SIZE);
    ret = memcmp(quote->report_body.report_data.d, shaSum, SHA256_DIGEST_SIZE);
    assert(ret == 0);

    return ret;
}

int verify_ias_report_signature(attestation_verification_report_t* attn_report){
    DecodedCert crt;
    int ret;

    uint8_t der[4096];
    int der_len;
    der_len = wolfSSL_CertPemToDer(attn_report->ias_sign_cert, attn_report->ias_sign_cert_len,
                                   der, sizeof(der),
                                   CERT_TYPE);
    assert(der_len > 0);
    
    InitDecodedCert(&crt, der, der_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);

    RsaKey rsaKey;
    unsigned int idx = 0;
    
    ret = wc_InitRsaKey(&rsaKey, NULL);
    assert(ret == 0);
    ret = wc_RsaPublicKeyDecode(crt.publicKey, &idx, &rsaKey, crt.pubKeySize);
    assert(ret == 0);

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256,
                             /* This is required such that signature
                                matches what OpenSSL produces. OpenSSL
                                embeds the hash in an ASN.1 structure
                                before signing it. */
                             WC_SIGNATURE_TYPE_RSA_W_ENC,
                             attn_report->ias_report, attn_report->ias_report_len,
                             attn_report->ias_report_signature, attn_report->ias_report_signature_len,
                             &rsaKey, sizeof(rsaKey));

    FreeDecodedCert(&crt);
    wc_FreeRsaKey(&rsaKey);

    return ret;
}

int verify_ias_certificate_chain(attestation_verification_report_t* attn_report) {
    WOLFSSL_CERT_MANAGER* cm;

    cm = wolfSSL_CertManagerNew();
    assert(cm != NULL);

    /* like load verify locations, 1 for success, < 0 for error */
    int ret = wolfSSL_CertManagerLoadCABuffer(cm, ias_sign_ca_cert_der,
                                              ias_sign_ca_cert_der_len,
                                              SSL_FILETYPE_ASN1);
    assert(ret == 1);
    
    ret = wolfSSL_CertManagerVerifyBuffer(cm, attn_report->ias_sign_cert,
                                          attn_report->ias_sign_cert_len,
                                          SSL_FILETYPE_PEM);
    assert(ret == SSL_SUCCESS);
    
    wolfSSL_CertManagerFree(cm);
    cm = NULL;
    
    return 0;
}

/**
 * Check if isvEnclaveQuoteStatus is "OK"
 * (cf. https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf,
 * pg. 24).
 *
 * @return 0 if verified successfully, 1 otherwise.
 */
int verify_enclave_quote_status(const char* ias_report, int ias_report_len) {
    // Move ias_report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[ias_report_len + 1];
    memcpy(buf, ias_report, ias_report_len);
    buf[ias_report_len] = '\0';
    
    const char* json_string = "\"isvEnclaveQuoteStatus\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);

    const char* status_OK = "OK\"";
    if (0 == strncmp(p_begin, status_OK, strlen(status_OK))) return 0;

//#ifdef SGX_GROUP_OUT_OF_DATE
    const char* status_outdated = "GROUP_OUT_OF_DATE\"";
    if (0 == strncmp(p_begin, status_outdated, strlen(status_outdated))) {
        eprintf("\t + (%s) Verified Attestation - WARNING: GROUP_OUT_OF_DATE\n", __FUNCTION__);
        return 0;
    }
//#endif
    return 1;
}

int epid_verify_sgx_cert_extensions(uint8_t* der_crt, uint32_t der_crt_len) {
    attestation_verification_report_t attn_report;

    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);
    
    extract_x509_extensions(crt.extensions, crt.extensionsSz, &attn_report);

    /* Base64 decode attestation report signature. */
    uint8_t sig_base64[sizeof(attn_report.ias_report_signature)];
    memcpy(sig_base64, attn_report.ias_report_signature, attn_report.ias_report_signature_len);

/* 
    int rc = Base64_Decode(sig_base64, attn_report.ias_report_signature_len,
                           attn_report.ias_report_signature, &attn_report.ias_report_signature_len);
   assert(0 == rc);
*/
#if DEBUG_CHALLENGER
    //edividerWithText("Signature");
    //eprintf("%.*s\n", sig_base64, attn_report.ias_report_signature_len);
    //edivider();
#endif

    base64_decode_wbuf(sig_base64, attn_report.ias_report_signature_len,
        attn_report.ias_report_signature, (size_t *)&attn_report.ias_report_signature_len);

#ifdef DEBUG_CHALLENGER
    edividerWithText("Signature Decoded");
    eprintf("%s\n", hexstring(attn_report.ias_report_signature, attn_report.ias_report_signature_len));
    edivider();
#endif

    ret = verify_ias_certificate_chain(&attn_report);
    assert(ret == 0);

    ret = verify_ias_report_signature(&attn_report);
    assert(ret == 0);

    ret = verify_enclave_quote_status((const char*) attn_report.ias_report,
                                      attn_report.ias_report_len);
    assert(ret == 0);

    sgx_quote_t quote = {0, };
    get_quote_from_report(attn_report.ias_report,
                          attn_report.ias_report_len,
                          &quote);

    ret = verify_report_data_against_server_cert(&crt, &quote);
    assert(ret == 0);

    FreeDecodedCert(&crt);

    return 0;
}

/**
 * Pretty-print information of EPID-based RA-TLS certificate to file descriptor.
 */
static
void dprintf_epid_ratls_cert (int fd, uint8_t* der_crt, uint32_t der_crt_len) {
    attestation_verification_report_t report;
    extract_x509_extensions(der_crt, der_crt_len, &report);
    edividerWithText("Intel Attestation Service Report");
    eprintf("%.*s\n", report.ias_report_len, report.ias_report);
    edivider();
}

void dprintf_ratls_cert(int fd, uint8_t* der_crt, uint32_t der_crt_len) {
    assert(is_epid_ratls_cert(der_crt, der_crt_len));
    dprintf_epid_ratls_cert(fd, der_crt, der_crt_len);
    sgx_quote_t quote;
    get_quote_from_cert(der_crt, der_crt_len, &quote);
    sgx_report_body_t* body = &quote.report_body;
    eprintf("MRENCLAVE = %s\n", hexstring(body->mr_enclave.m, SGX_HASH_SIZE));
    eprintf("MRSIGNER  = %s\n", hexstring(body->mr_signer.m, SGX_HASH_SIZE));
}


