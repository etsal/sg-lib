#include "sg_common.h"
#include "sgx_errlist.h"

void
eprint_sgx_err(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				eprintf("Info: %s\n", sgx_errlist[idx].sug);
			eprintf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		eprintf(
		    "Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer "
		    "Reference\" for more details.\n",
		    ret);
}
