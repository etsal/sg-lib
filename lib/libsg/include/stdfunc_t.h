#ifndef STDFUNC_T_H__
#define STDFUNC_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t SGX_CDECL ocall_exit(int s);
sgx_status_t SGX_CDECL ocall_eprintf(const char* str);
sgx_status_t SGX_CDECL ocall_lprintf(const char* str);
sgx_status_t SGX_CDECL ocall_sleep(int time);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
