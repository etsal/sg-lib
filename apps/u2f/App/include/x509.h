#ifndef _X509_H_
#define _X509_H_

#include <stdint.h>

#define TBS_ARG_MAX 120
#define UTC_TIME_SZ 120

typedef struct _tbs_cert_details {
	char not_before[UTC_TIME_SZ];
	char not_after[UTC_TIME_SZ];

	char subj_common_name[TBS_ARG_MAX];
	char subj_org_name[TBS_ARG_MAX];
	char subj_cntry_name[TBS_ARG_MAX];
} tbs_cert_details;

size_t generate_tbs_certificate(unsigned char *dest,
    const unsigned char *subject_pubkey, size_t subject_pubkey_len,
    tbs_cert_details details);

size_t generate_final_certificate(unsigned char *dest, unsigned char *tbs_cert,
    size_t tbs_cert_len, unsigned char *signed_tbs_cert,
    size_t signed_tbs_cert_len);

#endif