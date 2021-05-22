#include <assert.h>

#include "attester.h"	// key_and_x509
#include "challenger.h" // get_quote_from_cert(), verify_sgx_cert_extensions()
#include "ra_tls.h"
#include "sg_common.h"
#include "sg_stdfunc.h"
#include "wolfssl_enclave.h"
/*
 * For ocalls
 */
#include "networking_internal.h"
#include "sg_t.h"

#define PORT "7777"

//#define RA_TLS_DEBUG 1

extern ra_tls_options_t global_opts;

static int
host_bind(const char *host, const char *port)
{
	int ret = -1;
	sgx_status_t status = ocall_host_bind(&ret, host, port);
	if (status != SGX_SUCCESS) {
		return -1;
	}
	return ret;
}

static int
host_connect(const char *host, const char *port)
{
	int ret = -1;
	sgx_status_t status = ocall_host_connect(&ret, host, port);
	if (status != SGX_SUCCESS) {
		return -1;
	}
	return ret;
}

static int
accept_client(int sock_fd)
{
	int ret = -1;
	sgx_status_t status = ocall_accept_client(&ret, sock_fd);
	if (status != SGX_SUCCESS) {
		return -1;
	}
	return ret;
}

static int
cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
	(void)preverify;
	int ret = verify_sgx_cert_extensions(
	    store->certs->buffer, store->certs->length);
#ifdef RA_TLS_DEBUG
	eprintf("\t+ Verifying SGX certificate extenstions ... %s\n",
	    __FUNCTION__, ret == 0 ? "Success" : "Failure");
#endif
	return !ret;
}

void
init_ratls_server(ratls_ctx_t *ctx, key_cert_t *kc)
{
	// Key need to be generated with create_key_and_x509
	assert(kc->der_key_len > 0 && kc->der_cert_len > 0);

	ctx->sockfd = host_bind(NULL, PORT);
	if (!(ctx->sockfd > 0)) {
		eprintf("%s : host bind failed\n", __FUNCTION__);
		exit(1);
	}
	if (enc_wolfSSL_Init() != SSL_SUCCESS) {
		eprintf("%s : wolfssl_Init failed\n", __FUNCTION__);
		exit(1);
	}
	ctx->method = enc_wolfTLSv1_2_server_method();
	ctx->ctx = enc_wolfSSL_CTX_new(ctx->method);
	if (ctx->ctx < 0) {
		eprintf("%s : enc_wolfSSL_CTX_new\n", __FUNCTION__);
		exit(1);
	}
	// Load server certificates into WOLFSSL_CTX
	int ret = enc_wolfSSL_CTX_use_certificate_buffer(
	    ctx->ctx, kc->der_cert, kc->der_cert_len, SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		eprintf(
		    "%s : enc_wolfSSL_CTX_use_certificate_chain_buffer_format failed\n",
		    __FUNCTION__);
		exit(1);
	}
	// Load server key into WOLFSSL_CTX
	ret = enc_wolfSSL_CTX_use_PrivateKey_buffer(
	    ctx->ctx, kc->der_key, kc->der_key_len, SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		eprintf("%s : wolfSSL_CTX_use_PrivateKey_buffer failed\n",
		    __FUNCTION__);
		exit(1);
	}
	// NEW
	ret = enc_wolfSSL_CTX_load_verify_buffer(
	    ctx->ctx, kc->der_cert, kc->der_cert_len, SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		eprintf("%s : wolfSSL_CTX_load_verify_buffer failed\n",
		    __FUNCTION__);
		exit(1);
	}
	// NEW: Set mutual authentication
	enc_wolfSSL_CTX_set_verify(ctx->ctx,
	    WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	    cert_verify_callback);
}

int
init_ratls_client(ratls_ctx_t *ctx, key_cert_t *kc, const char *host)
{
#ifdef RA_TLS_DEBUG
	eprintf("\t+ %s : start\n", __FUNCTION__);
#endif

	int ret = enc_wolfSSL_Init();
	if (ret != SSL_SUCCESS) {
		eprintf("%s : enc_wolfSSL_Init failed\n", __FUNCTION__);
		return 1;
	}
	// eprintf("\t+ enc_wolfTLSv1_2_client_method\n");
	ctx->method = enc_wolfTLSv1_2_client_method();
	// eprintf("\t+ enc_wolfSSL_CTX_new\n");
	ctx->ctx = enc_wolfSSL_CTX_new(ctx->method);
	if (ctx < 0) {
		eprintf("%s : enc_wolfSSL_CTX_new failed\n", __FUNCTION__);
		// exit(1);
		return 1;
	}
	// eprintf("\t+ enc_wolfSSL_CTX_use_certificate_buffer\n");
	// I think this the chain isnt needed here
	ret = enc_wolfSSL_CTX_use_certificate_buffer(
	    ctx->ctx, kc->der_cert, kc->der_cert_len, SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		eprintf("%s : enc_wolfSSL_CTX_use_certificate_buffer failed\n",
		    __FUNCTION__);
		// exit(1);
		return 1;
	}

	// eprintf("\t+ enc_wolfSSL_CTX_use_PrivateKey_buffer\n");
	ret = enc_wolfSSL_CTX_use_PrivateKey_buffer(
	    ctx->ctx, kc->der_key, kc->der_key_len, SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		eprintf("wolfSSL_CTX_use_PrivateKey_buffer failed\n");
		// exit(1);
		return 1;
	}

	/*
	  ret = enc_wolfSSL_CTX_load_verify_buffer(ctx->ctx, kc->der_cert,
	  kc->der_cert_len, SSL_FILETYPE_ASN1); if (ret != SSL_SUCCESS) {
	      eprintf("Error loading cert\n");
	      exit(1);
	  }
	*/
#ifdef RA_TLS_DEBUG
	eprintf("\t+ %s : Calling host_connect\n", __FUNCTION__);
#endif

	ctx->sockfd = host_connect(host, PORT);
	if (!(ctx->sockfd > 0)) {
		eprintf("%s : host_connect failed\n", __FUNCTION__);
		return 1;
	}

	// Enable client authentication
	//    eprintf("\t+ enc_wolfSSL_CTX_set_verify\n");
	ret = enc_wolfSSL_CTX_set_verify(
	    ctx->ctx, WOLFSSL_VERIFY_PEER, cert_verify_callback);
	if (ret != SSL_SUCCESS) {
		eprintf(
		    "%s : enc_wolfSSL_CTX_set_verify failed\n", __FUNCTION__);
		return 1;
	}

	// Create new SSL session
	//	eprintf("\t+ enc_wolfSSL_new\n");
	ctx->ssl = enc_wolfSSL_new(ctx->ctx);
	if (ctx->ssl < 0) {
		eprintf("%s : wolfSSL_new failed\n", __FUNCTION__);
		exit(1);
	}

	// Attach wolfSSL to the socket
	ret = enc_wolfSSL_set_fd(ctx->ssl, ctx->sockfd);
	if (ret != SSL_SUCCESS) {
		eprintf("%s : wolfSSL_set_fd failed\n", __FUNCTION__);
		exit(1);
	}

	//    eprintf("\t+ enc_wolfSSL_connect\n");
	ret = enc_wolfSSL_connect(ctx->ssl);
	if (ret != SSL_SUCCESS) {
		eprintf("%s : enc_wolfSSL_connect failed\n", __FUNCTION__);
		exit(1);
	}

	// RA check
	WOLFSSL_X509 *srv_crt;
	int derSz;
	const unsigned char *der;

	// eprintf("\t+ enc_wolfSSL_get_peer_certificate\n");
	srv_crt = enc_wolfSSL_get_peer_certificate(ctx->ssl);
	der = wolfSSL_X509_get_der(srv_crt, &derSz);

	sgx_quote_t quote;
	memset(&quote, 0, sizeof(sgx_quote_t));
	get_quote_from_cert(der, derSz, &quote);
	sgx_report_body_t *body = &quote.report_body;

#ifdef RA_TLS_DEBUG
	eprintf("\t+ %s : Checking peer's identity\n", __FUNCTION__);
	eprintf("\t  + Server's SGX identity:\n");
	eprintf("\t    . MRENCLAVE = %s\n",
	    hexstring(body->mr_enclave.m, SGX_HASH_SIZE));
	eprintf("\t    . MRSIGNER  = %s\n",
	    hexstring(body->mr_signer.m, SGX_HASH_SIZE));
#endif

	return 0;
}

int
listen_ratls_server(ratls_ctx_t *ctx)
{
	sgx_status_t status;
	int ret = 0;
	char buff[256];
	size_t len;

#ifdef RA_TLS_DEBUG
	eprintf("\t+ %s : start\n", __FUNCTION__);
#endif

	// TODO: make sure we only have 1 ssl session at a time
	if (ctx->cli_sockfd) {
		eprintf("%s : cli_sockfd is set\n", __FUNCTION__);
		exit(1);
	}

	ctx->cli_sockfd = accept_client(ctx->sockfd);
	if (ctx->cli_sockfd < 0 || ctx->cli_sockfd == 0) {
		eprintf("%s : ocall_accept_client failed\n", __FUNCTION__);
		exit(1);
	}

	// Create new SSL session
	ctx->ssl = enc_wolfSSL_new(ctx->ctx);
	if (ctx->ssl < 0) {
		eprintf("%s : wolfSSL_new failed\n", __FUNCTION__);
		exit(1);
	}

	// Attach wolfSSL to the socket
	ret = enc_wolfSSL_set_fd(ctx->ssl, ctx->cli_sockfd);
	if (ret != SSL_SUCCESS) {
		eprintf("%s : wolfSSL_set_fd failed\n", __FUNCTION__);
		exit(1);
	}

	// NEW:
	ret = enc_wolfSSL_negotiate(ctx->ssl);
	if (ret != SSL_SUCCESS) {
		eprintf("%s : enc_wolfSSL_negotiate failed\n", __FUNCTION__);
		exit(1);
	}

#ifdef RA_TLS_DEBUG
	eprintf("\t+ %s : Client connected successfully\n", __FUNCTION__);
#endif

	WOLFSSL_X509 *cli_crt;
	int derSz;
	const unsigned char *der;

	cli_crt = enc_wolfSSL_get_peer_certificate(ctx->ssl);
	der = wolfSSL_X509_get_der(cli_crt, &derSz);

	sgx_quote_t quote;
	get_quote_from_cert(der, derSz, &quote);
	sgx_report_body_t *body = &quote.report_body;

#ifdef RA_TLS_DEBUG
	// TODO: check this properly, function should return error on failure
	eprintf("\t  + Client's SGX identity:\n");
	eprintf("\t    . MRENCLAVE = %s\n",
	    hexstring(body->mr_enclave.m, SGX_HASH_SIZE));
	eprintf("\t    . MRSIGNER  = %s\n",
	    hexstring(body->mr_signer.m, SGX_HASH_SIZE));
#endif

	return 0;
}

int
read_ratls(ratls_ctx_t *ctx, uint8_t *data, size_t len)
{
	int ret = enc_wolfSSL_read(ctx->ssl, data, len);
	if (ret == -1) {
		eprintf("%s : Server read failed\n", __FUNCTION__);
		exit(1);
	}
	return ret;
}

int
write_ratls(ratls_ctx_t *ctx, uint8_t *data, size_t len)
{
	int ret = enc_wolfSSL_write(ctx->ssl, data, len);
	if (ret != len) {
		eprintf("%s : Server write failed\n", __FUNCTION__);
		exit(1);
	}
	return ret;
}

void
close_ratls_server(ratls_ctx_t *ctx)
{
	enc_wolfSSL_free(ctx->ssl);
	ocall_close(NULL, ctx->cli_sockfd); // Don't care about retval
	ctx->cli_sockfd = 0;
}

void
destroy_ratls(ratls_ctx_t *ctx)
{
	enc_wolfSSL_free(ctx->ssl);	// If server this might be free already
	enc_wolfSSL_CTX_free(ctx->ctx); // Free the wolfSSL context object
	enc_wolfSSL_Cleanup();		// Cleanup the wolfSSL environment
	ocall_close(
	    NULL, ctx->sockfd); // Close the socket listening for clients
	memset(ctx, 0, sizeof(ratls_ctx_t));
}

void
protobuf_pack_keycert(key_cert_t *keycert, Keycert *kc)
{
	kc->key_type = keycert->key_type;

	kc->key.len = keycert->der_key_len;
	kc->key.data = malloc(keycert->der_key_len);
	memcpy(kc->key.data, keycert->der_key, keycert->der_key_len);

	kc->cert.len = keycert->der_cert_len;
	kc->cert.data = malloc(keycert->der_cert_len);
	memcpy(kc->cert.data, keycert->der_cert, keycert->der_cert_len);
}

void
protobuf_free_packed_keycert(Keycert *kc)
{
	free(kc->key.data);
	free(kc->cert.data);
}

void
protobuf_unpack_keycert(key_cert_t *keycert, Keycert *kc)
{
	keycert->key_type = kc->key_type;

	assert(!(kc->key.len > DER_KEY_LEN));
	assert(!(kc->cert.len > DER_CERT_LEN));

	keycert->der_key_len = kc->key.len;
	memcpy(keycert->der_key, kc->key.data, kc->key.len);

	keycert->der_cert_len = kc->cert.len;
	memcpy(keycert->der_cert, kc->cert.data, kc->cert.len);
}

