#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "ra_tls.h"
#include "ra_tls_util.h"
#include "attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_test();
int ecall_process_request(uint8_t* data, size_t data_len);
int ecall_init_sg(const char* config_str, size_t config_str_len);
int ecall_recieve_connections_sg();
int ecall_initiate_connections_sg();
int ecall_verify_connections_sg();
int ecall_poll_and_process_updates();
int ecall_add_user(const char* username, const char* password);
int ecall_auth_user(const char* username, const char* password);

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL ocall_exit(int s);
sgx_status_t SGX_CDECL ocall_eprintf(const char* str);
sgx_status_t SGX_CDECL ocall_lprintf(const char* str);
sgx_status_t SGX_CDECL ocall_sleep(int time);
sgx_status_t SGX_CDECL ocall_access(int* retval, const char* filename);
sgx_status_t SGX_CDECL ocall_store(int* retval, const char* filename, const uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL ocall_load_len(int* retval, const char* filename, size_t* len);
sgx_status_t SGX_CDECL ocall_load(int* retval, const char* filename, uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL ocall_write(int* retval, const int* fd, const unsigned char* buf, size_t len);
sgx_status_t SGX_CDECL ocall_read(int* retval, const int* fd, unsigned char* buf, size_t len);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_host_bind(int* retval, const char* host, const char* port);
sgx_status_t SGX_CDECL ocall_host_connect(int* retval, const char* host, const char* port);
sgx_status_t SGX_CDECL ocall_accept_client(int* retval, int sock_fd);
sgx_status_t SGX_CDECL ocall_gethostname(char* host);
sgx_status_t SGX_CDECL ocall_init_networking();
sgx_status_t SGX_CDECL ocall_poll_and_process_updates(int* retval, int* active_fds, int* check_fds, size_t len);
sgx_status_t SGX_CDECL ocall_low_res_time(int* time);
sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_target_info_t* target_info);
sgx_status_t SGX_CDECL ocall_remote_attestation(sgx_report_t* report, const ra_tls_options_t* opts, attestation_verification_report_t* attn_report);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
