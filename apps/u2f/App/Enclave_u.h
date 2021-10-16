#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "ra_tls.h"
#include "ra_tls_util.h"
#include "attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_exit, (int s));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_eprintf, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lprintf, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (int time));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_atoi, (const char* str, int* str_int));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_access, (const char* filename));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_store, (const char* filename, const uint8_t* buf, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_len, (const char* filename, size_t* len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load, (const char* filename, uint8_t* buf, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (const int* fd, const unsigned char* buf, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (const int* fd, unsigned char* buf, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fopen, (const char* filepath, const char* mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fwrite, (const char* buf, int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fclose, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_host_bind, (const char* host, const char* port));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_host_connect, (const char* host, const char* port));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_accept_client, (int sock_fd));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostname, (char* host));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostip, (char* ip));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_init_networking, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_poll_and_process_updates, (int* active_fds, int* check_fds, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_low_res_time, (int* time));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int sockfd, void* buf, size_t len, int flags));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int sockfd, const void* buf, size_t len, int flags));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_init_quote, (sgx_target_info_t* target_info));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remote_attestation, (sgx_report_t* report, const ra_tls_options_t* opts, attestation_verification_report_t* attn_report));

sgx_status_t ecall_init_device(sgx_enclave_id_t eid, int uid);
sgx_status_t ecall_get_cert(sgx_enclave_id_t eid, int* retval, unsigned char* buf, size_t len);
sgx_status_t ecall_generate_site_keys(sgx_enclave_id_t eid, unsigned char* key_handle, size_t key_handle_len, unsigned char* public_key, size_t public_key_len);
sgx_status_t ecall_generate_registration_signature(sgx_enclave_id_t eid, int* retval, const unsigned char* key_handle, size_t key_handle_len, const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len);
sgx_status_t ecall_generate_authentication_signature(sgx_enclave_id_t eid, int* retval, const unsigned char* key_handle, size_t key_handle_len, const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len);
sgx_status_t ecall_inc_and_get_site_counter(sgx_enclave_id_t eid, uint32_t* retval, const unsigned char* key_handle, size_t key_handle_len);
sgx_status_t ecall_listen_updates(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_send_update(sgx_enclave_id_t eid, int* retval, const char* host);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
