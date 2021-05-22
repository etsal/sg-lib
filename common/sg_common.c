#include <assert.h>
#include <stdio.h> /* vsnprintf */
#include <stdlib.h>
#include <string.h>

#include "sg_common.h"

//#ifdef __ENCLAVE__
#include "sg_t.h" /* ocall_* */
//#endif

#define LINE_SHORT_LEN 4
#define LINE_MAX_LEN 76

#ifdef __APP__
FILE *log_fp;
#endif

/*static*/ char *_hex_buffer = NULL;
static size_t _hex_buffer_size = 0;
static const char _hextable[] = "0123456789abcdef";

static void report_body_details(sgx_report_body_t *q);
static void quote_details(const sgx_quote_t *q, int flag);

int
eprintf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list va;
	int rv;

	va_start(va, fmt);
#if defined(__ENCLAVE__)
	vsnprintf(buf, BUFSIZ, fmt, va);
	va_end(va);
	ocall_eprintf(buf);
	rv = (int)strnlen(buf, BUFSIZ - 1) + 1;
#endif
#if defined(__APP__)
	rv = vfprintf(stderr, fmt, va);
	va_end(va);
#endif
	return rv;
}

int
lprintf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list va;
	int rv;

	va_start(va, fmt);
#if defined(__ENCLAVE__)
	vsnprintf(buf, BUFSIZ, fmt, va);
	va_end(va);
	ocall_lprintf(buf);
	rv = (int)strnlen(buf, BUFSIZ - 1) + 1;
#endif
#if defined(__APP__)
	assert(log_fp);
	rv = vfprintf(log_fp, fmt, va);
	va_end(va);
	fflush(log_fp);
#endif
	return rv;
}

const char *
hexstring(const void *vsrc, size_t len)
{
	size_t i, bsz;
	const unsigned char *src = (const unsigned char *)vsrc;
	char *bp, *tmp;

	bsz = len * 2 + 1; /* Make room for NULL byte */
	if (bsz >= _hex_buffer_size) {
		/* Allocate in 1K increments. Make room for the NULL byte. */

		/*
			tmp = malloc(new_sz);
			memcpy(tmp, _hex_buffer, _hex_buffer_size);
			_hex_buffer_size= newsz;
			free(_hex_buffer);
		       _hex_buffer= tmp;

		  */
		size_t newsz = 1024 * (bsz / 1024) + ((bsz % 1024) ? 1024 : 0);
		_hex_buffer_size = newsz;
		_hex_buffer = (char *)realloc(_hex_buffer, newsz);
		if (_hex_buffer == NULL) {
			return "(out of memory)";
		}
	}
	unsigned int idx = 0;
	for (i = 0, bp = _hex_buffer; i < len; ++i) {
		idx = (src[i] >> 4) % strlen(_hextable);
		*bp = _hextable[idx];
		++bp;
		*bp = _hextable[src[i] & 0xf];
		++bp;
	}
	_hex_buffer[len * 2] = 0;

	return (const char *)_hex_buffer;
}

void
eprint_hexstring(const void *vsrc, size_t len)
{
	const char *fmt;
#ifdef __ENCLAVE__
	fmt = hexstring(vsrc, len);
	ocall_eprintf(fmt);
#elif __APP__
	fprintf(stderr, "%s", hexstring(vsrc, len));
#endif
}

void
lprint_hexstring(const void *vsrc, size_t len)
{
	const char *fmt;
#ifdef __ENCLAVE__
	fmt = hexstring(vsrc, len);
	ocall_lprintf(fmt);
#elif __APP__
	lprintf("%s", hexstring(vsrc, len));
#endif
}

void
eprint_bytes(const void *src, size_t len)
{
	uint8_t *buf = (uint8_t *)src;
	for (int i = 0; i < len; ++i) {
		eprintf("%02x", buf[i]);
	}
	eprintf("\n");
}

void
edividerWithText(const char *text)
{
	char line[LINE_MAX_LEN];
	int len = strlen(text);

#ifdef __ENCLAVE__
	char buf[BUFSIZ];
	memset(line, '-', LINE_MAX_LEN);
	buf[0] = '\n';
	buf[1] = '-';
	buf[2] = '-';
	buf[3] = '-';
	buf[4] = ' ';
	buf[5] = '\0';
	ocall_eprintf(buf);
	ocall_eprintf(text);
	len = LINE_MAX_LEN - len - LINE_SHORT_LEN - 2;
	line[0] = ' ';
	line[len] = '\n';
	line[len + 1] = '\0';
	ocall_eprintf(line);
#elif __APP__
	memset(line, '-', LINE_MAX_LEN);
	line[LINE_MAX_LEN - len - LINE_SHORT_LEN - 2] = '\0';
	fprintf(stderr, "\n---- ");
	fprintf(stderr, "%s", text);
	fprintf(stderr, " %s\n", line);
#endif
}

void
ldividerWithText(const char *text)
{
	char line[LINE_MAX_LEN];
	int len = strlen(text);

#ifdef __ENCLAVE__
	char buf[BUFSIZ];
	memset(line, '-', LINE_MAX_LEN);
	buf[0] = '\n';
	buf[1] = '-';
	buf[2] = '-';
	buf[3] = '-';
	buf[4] = ' ';
	buf[5] = '\0';
	ocall_lprintf(buf);
	ocall_lprintf(text);
	len = LINE_MAX_LEN - len - LINE_SHORT_LEN - 2;
	line[0] = ' ';
	line[len] = '\n';
	line[len + 1] = '\0';
	ocall_lprintf(line);
#elif __APP__
	assert(log_fp);
	memset(line, '-', LINE_MAX_LEN);
	line[LINE_MAX_LEN - len - LINE_SHORT_LEN - 2] = '\0';
	fprintf(log_fp, "\n---- ");
	fprintf(log_fp, "%s", text);
	fprintf(log_fp, " %s\n", line);
	fflush(log_fp);
#endif
}

void
edivider()
{
	char line[LINE_MAX_LEN];
	memset(line, '-', LINE_MAX_LEN);
	line[LINE_MAX_LEN - 3] = '\n';
	line[LINE_MAX_LEN - 2] = '\n';
	line[LINE_MAX_LEN - 1] = '\0';
#ifdef __ENCLAVE__
	ocall_eprintf(line);
#elif __APP__
	fprintf(stderr, "%s\n", line);
#endif
}

void
ldivider()
{
	char line[LINE_MAX_LEN];
	memset(line, '-', LINE_MAX_LEN);
	line[LINE_MAX_LEN - 2] = '\n';
	line[LINE_MAX_LEN - 1] = '\0';
#ifdef __ENCLAVE__
	ocall_lprintf(line);
#elif __APP__
	assert(log_fp);
	fprintf(log_fp, "%s", line);
	fflush(log_fp);
#endif
}

void
print_msg1_details(const sgx_ra_msg1_t *msg1)
{
	ldividerWithText("Msg1 Details");
	lprintf("msg1.g_a.gx = ");
	lprint_hexstring(msg1->g_a.gx, 32);
	lprintf("\nmsg1.g_a.gy = ");
	lprint_hexstring(msg1->g_a.gy, 32);
	lprintf(
	    "\nmsg1.gid    = %s\n", hexstring(&msg1->gid, sizeof(msg1->gid)));
	ldivider();
}

void
print_msg2_details(sgx_ra_msg2_t *msg2)
{
	ldividerWithText("Msg2 Details");
	lprintf("sizeof(sgx_ra_msg2_t) = %d\n", sizeof(sgx_ra_msg2_t));
	lprintf("msg2.g_b.gx      = %s\n",
	    hexstring(&((msg2->g_b).gx), sizeof(msg2->g_b.gx)));
	lprintf("msg2.g_b.gy      = %s\n",
	    hexstring(&((msg2->g_b).gy), sizeof(msg2->g_b.gy)));
	lprintf("msg2.spid        = %s\n",
	    hexstring(&msg2->spid, sizeof(msg2->spid)));
	lprintf("msg2.quote_type  = %s = %d\n",
	    hexstring(&msg2->quote_type, sizeof(msg2->quote_type)),
	    msg2->quote_type);
	lprintf("msg2.kdf_id      = %s = %d\n",
	    hexstring(&msg2->kdf_id, sizeof(msg2->kdf_id)), msg2->quote_type);
	lprintf("msg2.sign_ga_gb  = %s\n",
	    hexstring(&msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga)));
	lprintf("msg2.mac         = %s\n",
	    hexstring(&msg2->mac, sizeof(msg2->mac)));
	lprintf("msg2.sig_rl_size = %s\n",
	    hexstring(&msg2->sig_rl_size, sizeof(msg2->sig_rl_size)));
	lprintf(
	    "msg2.sig_rl = %s\n", hexstring(&msg2->sig_rl, msg2->sig_rl_size));
	ldivider();
}

void
print_msg3_details(sgx_ra_msg3_t *msg3, uint32_t msg3_sz)
{
	ldividerWithText("Msg3 Details");
	lprintf("msg3.mac         = ");
	lprint_hexstring(msg3->mac, sizeof(msg3->mac));
	lprintf("\nmsg3.g_a.gx      = ");
	lprint_hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx));
	lprintf("\nmsg3.g_a.gy      = ");
	lprint_hexstring(msg3->g_a.gy, sizeof(msg3->g_a.gy));
	lprintf("\nmsg3.quote       = ");
	lprint_hexstring(msg3->quote, msg3_sz - sizeof(sgx_ra_msg3_t));
	lprintf("\n");
	sgx_quote_t *quote = (sgx_quote_t *)msg3->quote;
	quote_details(quote, 1);
	ldivider();
}

void
print_quote_details(const sgx_quote_t *q, int sig_flag)
{
	edividerWithText("Quote Details");
	eprintf("%s Signature\n", (sig_flag == 1) ? "With" : "Without");
	quote_details(q, sig_flag);
	edivider();
}

void
print_report_body_details(sgx_report_body_t *q)
{
	edividerWithText("sgx_report_body_t details");
	// print_report_details(q);
	edivider();
}

void
quote_details(const sgx_quote_t *q, int flag)
{
	eprintf("msg3.quote.version     = %s\n",
	    hexstring(&q->version, sizeof(uint16_t)));
	eprintf("msg3.quote.sign_type     = %s\n",
	    hexstring(&q->sign_type, sizeof(uint16_t)));
	eprintf("msg3.quote.epid_group_id = %s\n",
	    hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
	eprintf("msg3.quote.qe_svn        = %s\n",
	    hexstring(&q->qe_svn, sizeof(sgx_isv_svn_t)));
	eprintf("msg3.quote.pce_svn       = %s\n",
	    hexstring(&q->pce_svn, sizeof(sgx_isv_svn_t)));
	eprintf("msg3.quote.xeid          = %s\n",
	    hexstring(&q->xeid, sizeof(uint32_t)));
	eprintf("msg3.quote.basename      = %s\n",
	    hexstring(&q->basename, sizeof(sgx_basename_t)));
	eprintf("msg3.quote.report_body   = %s\n",
	    hexstring(&q->report_body, sizeof(sgx_report_body_t)));

	if (flag) {
		eprintf("msg3.quote.signature_len = %s = %d\n",
		    hexstring(&q->signature_len, sizeof(uint32_t)),
		    q->signature_len);

		if (q->signature_len < 0) {
			eprintf("msg3.quote_signature : error\n\n");
			return;
		}

		eprintf("msg3.quote.signature     = %s\n",
		    hexstring(&q->signature, q->signature_len));
	}
}

void
report_body_details(sgx_report_body_t *q)
{
	/*
	    eprintf("msg3.quote.report_body     = %s\n",
		hexstring(&q->body, sizeof(sgx_report_body_t)));
	    eprintf("msg3.quote.report.body     = %s\n",
		hexstring(&q->key_id, sizeof(sgx_key_id_t)));
	    eprintf("msg3.quote.report.body     = %s\n",
		hexstring(&q->mac, sizeof(sgx_mac_t)));
	*/
}
