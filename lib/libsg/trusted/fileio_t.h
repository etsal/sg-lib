#ifndef FILEIO_T_H__
#define FILEIO_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t SGX_CDECL ocall_access(int* retval, const char* filename);
sgx_status_t SGX_CDECL ocall_store(int* retval, const char* filename, const uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL ocall_load_len(int* retval, const char* filename, size_t* len);
sgx_status_t SGX_CDECL ocall_load(int* retval, const char* filename, uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL ocall_write(int* retval, const int* fd, const unsigned char* buf, size_t len);
sgx_status_t SGX_CDECL ocall_read(int* retval, const int* fd, unsigned char* buf, size_t len);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_fopen(int* retval, const char* filepath, const char* mode);
sgx_status_t SGX_CDECL ocall_fwrite(int* retval, const char* buf, int fd);
sgx_status_t SGX_CDECL ocall_fclose(int* retval, int fd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
