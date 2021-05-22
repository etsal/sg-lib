#ifndef __SG_COMMON_H__
#define __SG_COMMON_H__
#include <stdarg.h>
#include <stddef.h>

#include "protocol.h"
int eprintf(const char *fmt, ...);
int lprintf(const char *fmt, ...);

const char *hexstring(const void *vsrc, size_t len);
void eprint_hexstring(const void *src, size_t len);
void eprint_bytes(const void *src, size_t len);

void edividerWithText(const char *text);
void edivider();
void ldividerWithText(const char *text);
void ldivider();

void print_msg1_details(const sgx_ra_msg1_t *msg1);
void print_msg2_details(sgx_ra_msg2_t *msg2);
void print_msg3_details(sgx_ra_msg3_t *msg3, uint32_t msg3_sz);
void print_quote_details(const sgx_quote_t *q, int sig_flag);
void print_report_body_details(sgx_report_body_t *q);

#endif
