#include "errlist.h"
#include "sg_common.h"
#include "sgx_errlist.h"

void
eprint_err(int ret)
{
	size_t idx = 0;
	size_t ttl = sizeof errlist / sizeof errlist[0];

	if (ret & SGX_MASK)
		return eprint_sgx_err((sgx_status_t)ret & SGX_MASK_OFF);

	for (idx = 0; idx < ttl; idx++) {
		if (ret == errlist[idx].err) {
			if (NULL != errlist[idx].sug)
				eprintf("Info: %s\n", errlist[idx].sug);
			eprintf("Error: %s\n", errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		eprintf("Error code is 0x%X.\n", ret);
}
