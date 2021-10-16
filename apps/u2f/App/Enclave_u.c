#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_device_t {
	int ms_uid;
} ms_ecall_init_device_t;

typedef struct ms_ecall_get_cert_t {
	int ms_retval;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ecall_get_cert_t;

typedef struct ms_ecall_generate_site_keys_t {
	unsigned char* ms_key_handle;
	size_t ms_key_handle_len;
	unsigned char* ms_public_key;
	size_t ms_public_key_len;
} ms_ecall_generate_site_keys_t;

typedef struct ms_ecall_generate_registration_signature_t {
	int ms_retval;
	unsigned char* ms_key_handle;
	size_t ms_key_handle_len;
	unsigned char* ms_data;
	size_t ms_data_len;
	unsigned char* ms_signature;
	size_t ms_signature_len;
} ms_ecall_generate_registration_signature_t;

typedef struct ms_ecall_generate_authentication_signature_t {
	int ms_retval;
	unsigned char* ms_key_handle;
	size_t ms_key_handle_len;
	unsigned char* ms_data;
	size_t ms_data_len;
	unsigned char* ms_signature;
	size_t ms_signature_len;
} ms_ecall_generate_authentication_signature_t;

typedef struct ms_ecall_inc_and_get_site_counter_t {
	uint32_t ms_retval;
	unsigned char* ms_key_handle;
	size_t ms_key_handle_len;
} ms_ecall_inc_and_get_site_counter_t;

typedef struct ms_ecall_listen_updates_t {
	int ms_retval;
} ms_ecall_listen_updates_t;

typedef struct ms_ecall_send_update_t {
	int ms_retval;
	char* ms_host;
	size_t ms_host_len;
} ms_ecall_send_update_t;

typedef struct ms_ocall_exit_t {
	int ms_s;
} ms_ocall_exit_t;

typedef struct ms_ocall_eprintf_t {
	char* ms_str;
} ms_ocall_eprintf_t;

typedef struct ms_ocall_lprintf_t {
	char* ms_str;
} ms_ocall_lprintf_t;

typedef struct ms_ocall_sleep_t {
	int ms_time;
} ms_ocall_sleep_t;

typedef struct ms_ocall_atoi_t {
	char* ms_str;
	int* ms_str_int;
} ms_ocall_atoi_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_access_t {
	int ms_retval;
	char* ms_filename;
} ms_ocall_access_t;

typedef struct ms_ocall_store_t {
	int ms_retval;
	char* ms_filename;
	uint8_t* ms_buf;
	size_t ms_len;
} ms_ocall_store_t;

typedef struct ms_ocall_load_len_t {
	int ms_retval;
	char* ms_filename;
	size_t* ms_len;
} ms_ocall_load_len_t;

typedef struct ms_ocall_load_t {
	int ms_retval;
	char* ms_filename;
	uint8_t* ms_buf;
	size_t ms_len;
} ms_ocall_load_t;

typedef struct ms_ocall_write_t {
	int ms_retval;
	int* ms_fd;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_write_t;

typedef struct ms_ocall_read_t {
	int ms_retval;
	int* ms_fd;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_read_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_fopen_t {
	int ms_retval;
	char* ms_filepath;
	char* ms_mode;
} ms_ocall_fopen_t;

typedef struct ms_ocall_fwrite_t {
	int ms_retval;
	char* ms_buf;
	int ms_fd;
} ms_ocall_fwrite_t;

typedef struct ms_ocall_fclose_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fclose_t;

typedef struct ms_ocall_host_bind_t {
	int ms_retval;
	char* ms_host;
	char* ms_port;
} ms_ocall_host_bind_t;

typedef struct ms_ocall_host_connect_t {
	int ms_retval;
	char* ms_host;
	char* ms_port;
} ms_ocall_host_connect_t;

typedef struct ms_ocall_accept_client_t {
	int ms_retval;
	int ms_sock_fd;
} ms_ocall_accept_client_t;

typedef struct ms_ocall_gethostname_t {
	char* ms_host;
} ms_ocall_gethostname_t;

typedef struct ms_ocall_gethostip_t {
	char* ms_ip;
} ms_ocall_gethostip_t;

typedef struct ms_ocall_poll_and_process_updates_t {
	int ms_retval;
	int* ms_active_fds;
	int* ms_check_fds;
	size_t ms_len;
} ms_ocall_poll_and_process_updates_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

typedef struct ms_ocall_sgx_init_quote_t {
	sgx_target_info_t* ms_target_info;
} ms_ocall_sgx_init_quote_t;

typedef struct ms_ocall_remote_attestation_t {
	sgx_report_t* ms_report;
	ra_tls_options_t* ms_opts;
	attestation_verification_report_t* ms_attn_report;
} ms_ocall_remote_attestation_t;

static sgx_status_t SGX_CDECL Enclave_ocall_exit(void* pms)
{
	ms_ocall_exit_t* ms = SGX_CAST(ms_ocall_exit_t*, pms);
	ocall_exit(ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_eprintf(void* pms)
{
	ms_ocall_eprintf_t* ms = SGX_CAST(ms_ocall_eprintf_t*, pms);
	ocall_eprintf((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lprintf(void* pms)
{
	ms_ocall_lprintf_t* ms = SGX_CAST(ms_ocall_lprintf_t*, pms);
	ocall_lprintf((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ocall_sleep(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_atoi(void* pms)
{
	ms_ocall_atoi_t* ms = SGX_CAST(ms_ocall_atoi_t*, pms);
	ocall_atoi((const char*)ms->ms_str, ms->ms_str_int);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_access(void* pms)
{
	ms_ocall_access_t* ms = SGX_CAST(ms_ocall_access_t*, pms);
	ms->ms_retval = ocall_access((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_store(void* pms)
{
	ms_ocall_store_t* ms = SGX_CAST(ms_ocall_store_t*, pms);
	ms->ms_retval = ocall_store((const char*)ms->ms_filename, (const uint8_t*)ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_load_len(void* pms)
{
	ms_ocall_load_len_t* ms = SGX_CAST(ms_ocall_load_len_t*, pms);
	ms->ms_retval = ocall_load_len((const char*)ms->ms_filename, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_load(void* pms)
{
	ms_ocall_load_t* ms = SGX_CAST(ms_ocall_load_t*, pms);
	ms->ms_retval = ocall_load((const char*)ms->ms_filename, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write((const int*)ms->ms_fd, (const unsigned char*)ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read((const int*)ms->ms_fd, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fopen(void* pms)
{
	ms_ocall_fopen_t* ms = SGX_CAST(ms_ocall_fopen_t*, pms);
	ms->ms_retval = ocall_fopen((const char*)ms->ms_filepath, (const char*)ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fwrite(void* pms)
{
	ms_ocall_fwrite_t* ms = SGX_CAST(ms_ocall_fwrite_t*, pms);
	ms->ms_retval = ocall_fwrite((const char*)ms->ms_buf, ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fclose(void* pms)
{
	ms_ocall_fclose_t* ms = SGX_CAST(ms_ocall_fclose_t*, pms);
	ms->ms_retval = ocall_fclose(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_host_bind(void* pms)
{
	ms_ocall_host_bind_t* ms = SGX_CAST(ms_ocall_host_bind_t*, pms);
	ms->ms_retval = ocall_host_bind((const char*)ms->ms_host, (const char*)ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_host_connect(void* pms)
{
	ms_ocall_host_connect_t* ms = SGX_CAST(ms_ocall_host_connect_t*, pms);
	ms->ms_retval = ocall_host_connect((const char*)ms->ms_host, (const char*)ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_accept_client(void* pms)
{
	ms_ocall_accept_client_t* ms = SGX_CAST(ms_ocall_accept_client_t*, pms);
	ms->ms_retval = ocall_accept_client(ms->ms_sock_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gethostname(void* pms)
{
	ms_ocall_gethostname_t* ms = SGX_CAST(ms_ocall_gethostname_t*, pms);
	ocall_gethostname(ms->ms_host);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gethostip(void* pms)
{
	ms_ocall_gethostip_t* ms = SGX_CAST(ms_ocall_gethostip_t*, pms);
	ocall_gethostip(ms->ms_ip);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_init_networking(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_init_networking();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_poll_and_process_updates(void* pms)
{
	ms_ocall_poll_and_process_updates_t* ms = SGX_CAST(ms_ocall_poll_and_process_updates_t*, pms);
	ms->ms_retval = ocall_poll_and_process_updates(ms->ms_active_fds, ms->ms_check_fds, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, (const void*)ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_init_quote(void* pms)
{
	ms_ocall_sgx_init_quote_t* ms = SGX_CAST(ms_ocall_sgx_init_quote_t*, pms);
	ocall_sgx_init_quote(ms->ms_target_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_remote_attestation(void* pms)
{
	ms_ocall_remote_attestation_t* ms = SGX_CAST(ms_ocall_remote_attestation_t*, pms);
	ocall_remote_attestation(ms->ms_report, (const ra_tls_options_t*)ms->ms_opts, ms->ms_attn_report);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[36];
} ocall_table_Enclave = {
	36,
	{
		(void*)Enclave_ocall_exit,
		(void*)Enclave_ocall_eprintf,
		(void*)Enclave_ocall_lprintf,
		(void*)Enclave_ocall_sleep,
		(void*)Enclave_ocall_atoi,
		(void*)Enclave_create_session_ocall,
		(void*)Enclave_exchange_report_ocall,
		(void*)Enclave_close_session_ocall,
		(void*)Enclave_invoke_service_ocall,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_ocall_access,
		(void*)Enclave_ocall_store,
		(void*)Enclave_ocall_load_len,
		(void*)Enclave_ocall_load,
		(void*)Enclave_ocall_write,
		(void*)Enclave_ocall_read,
		(void*)Enclave_ocall_close,
		(void*)Enclave_ocall_fopen,
		(void*)Enclave_ocall_fwrite,
		(void*)Enclave_ocall_fclose,
		(void*)Enclave_ocall_host_bind,
		(void*)Enclave_ocall_host_connect,
		(void*)Enclave_ocall_accept_client,
		(void*)Enclave_ocall_gethostname,
		(void*)Enclave_ocall_gethostip,
		(void*)Enclave_ocall_init_networking,
		(void*)Enclave_ocall_poll_and_process_updates,
		(void*)Enclave_ocall_low_res_time,
		(void*)Enclave_ocall_recv,
		(void*)Enclave_ocall_send,
		(void*)Enclave_ocall_sgx_init_quote,
		(void*)Enclave_ocall_remote_attestation,
	}
};
sgx_status_t ecall_init_device(sgx_enclave_id_t eid, int uid)
{
	sgx_status_t status;
	ms_ecall_init_device_t ms;
	ms.ms_uid = uid;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_get_cert(sgx_enclave_id_t eid, int* retval, unsigned char* buf, size_t len)
{
	sgx_status_t status;
	ms_ecall_get_cert_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_generate_site_keys(sgx_enclave_id_t eid, unsigned char* key_handle, size_t key_handle_len, unsigned char* public_key, size_t public_key_len)
{
	sgx_status_t status;
	ms_ecall_generate_site_keys_t ms;
	ms.ms_key_handle = key_handle;
	ms.ms_key_handle_len = key_handle_len;
	ms.ms_public_key = public_key;
	ms.ms_public_key_len = public_key_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_generate_registration_signature(sgx_enclave_id_t eid, int* retval, const unsigned char* key_handle, size_t key_handle_len, const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len)
{
	sgx_status_t status;
	ms_ecall_generate_registration_signature_t ms;
	ms.ms_key_handle = (unsigned char*)key_handle;
	ms.ms_key_handle_len = key_handle_len;
	ms.ms_data = (unsigned char*)data;
	ms.ms_data_len = data_len;
	ms.ms_signature = signature;
	ms.ms_signature_len = signature_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_generate_authentication_signature(sgx_enclave_id_t eid, int* retval, const unsigned char* key_handle, size_t key_handle_len, const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len)
{
	sgx_status_t status;
	ms_ecall_generate_authentication_signature_t ms;
	ms.ms_key_handle = (unsigned char*)key_handle;
	ms.ms_key_handle_len = key_handle_len;
	ms.ms_data = (unsigned char*)data;
	ms.ms_data_len = data_len;
	ms.ms_signature = signature;
	ms.ms_signature_len = signature_len;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_inc_and_get_site_counter(sgx_enclave_id_t eid, uint32_t* retval, const unsigned char* key_handle, size_t key_handle_len)
{
	sgx_status_t status;
	ms_ecall_inc_and_get_site_counter_t ms;
	ms.ms_key_handle = (unsigned char*)key_handle;
	ms.ms_key_handle_len = key_handle_len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_listen_updates(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_listen_updates_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_send_update(sgx_enclave_id_t eid, int* retval, const char* host)
{
	sgx_status_t status;
	ms_ecall_send_update_t ms;
	ms.ms_host = (char*)host;
	ms.ms_host_len = host ? strlen(host) + 1 : 0;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

