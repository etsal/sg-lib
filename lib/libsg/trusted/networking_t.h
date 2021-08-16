#ifndef NETWORKING_T_H__
#define NETWORKING_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t SGX_CDECL ocall_host_bind(int* retval, const char* host, const char* port);
sgx_status_t SGX_CDECL ocall_host_connect(int* retval, const char* host, const char* port);
sgx_status_t SGX_CDECL ocall_accept_client(int* retval, int sock_fd);
sgx_status_t SGX_CDECL ocall_gethostname(char* host);
sgx_status_t SGX_CDECL ocall_gethostip(char* ip);
sgx_status_t SGX_CDECL ocall_init_networking();
sgx_status_t SGX_CDECL ocall_poll_and_process_updates(int* retval, int* active_fds, int* check_fds, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
