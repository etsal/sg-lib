/* This is useless but lets just use these functions for now */
#ifndef __WOLFSSL_ENCLAVE_H__
#define __WOLFSSL_ENCLAVE_H__

#include <stddef.h>

#include <wolfssl/ssl.h> // VerifyCallback

void enc_wolfSSL_Debugging_ON(void);
void enc_wolfSSL_Debugging_OFF(void);
int enc_wolfSSL_Init(void);
long enc_wolfTLSv1_2_client_method(void);
long enc_wolfTLSv1_2_server_method(void);
long enc_wolfSSL_CTX_new(long method);
int enc_wolfSSL_CTX_use_certificate_buffer(long id, const unsigned char* buf, long sz, int type);
int enc_wolfSSL_CTX_use_PrivateKey_buffer(long id, const unsigned char* buf, long sz, int type);
int enc_wolfSSL_CTX_load_verify_buffer(long id, const unsigned char* in, long sz, int format);
int enc_wolfSSL_CTX_set_verify(long id, int flags, VerifyCallback verify_callback);
int enc_wolfSSL_negotiate(long sslId);
WOLFSSL_X509 *enc_wolfSSL_get_peer_certificate(long sslId);
long enc_wolfSSL_new(long id);
int enc_wolfSSL_set_fd(long sslId, int fd);
int enc_wolfSSL_connect(long sslId);
int enc_wolfSSL_write(long sslId, const void* in, int sz);
int enc_wolfSSL_get_error(long sslId, int ret);
int enc_wolfSSL_read(long sslId, void* data, int sz);
void enc_wolfSSL_free(long sslId);
void enc_wolfSSL_CTX_free(long id);
int enc_wolfSSL_Cleanup(void);

int LowResTimer(void);
size_t recv(int sockfd, void *buf, size_t len, int flags); 
size_t send(int sockfd, const void *buf, size_t len, int flags);

#endif
