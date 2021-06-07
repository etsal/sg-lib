#ifndef _RA_TLS_H_
#define _RA_TLS_H_

#include <stdint.h>
#include <stddef.h>

#include "keycert.pb-c.h"

#define DER_KEY_LEN 2048    // Enough room for RSA 3072
#define DER_CERT_LEN 4096*4 

typedef struct {
  int key_type;
  uint8_t der_key[DER_KEY_LEN];
  uint8_t der_cert[DER_CERT_LEN];
  uint32_t der_key_len;
  uint32_t der_cert_len;
} key_cert_t;

typedef struct {
  // Network structures
  int sockfd;
  int cli_sockfd;
  // WolfSSL structures
  long method;
  long ctx;
  long ssl; 
} ratls_ctx_t;


//NEW
int accept_connections(ratls_ctx_t *server, ratls_ctx_t *client);
void cleanup_ratls(ratls_ctx_t *ctx);


void init_ratls();
void init_ratls_server(ratls_ctx_t *ctx, key_cert_t *kc);
int init_ratls_client(ratls_ctx_t *ctx, key_cert_t *kc, const char *host);
int listen_ratls_server(ratls_ctx_t *ctx);
int read_ratls(ratls_ctx_t *ctx, uint8_t *data, size_t len);
int write_ratls(ratls_ctx_t *ctx, uint8_t *data, size_t len);
void close_ratls_server(ratls_ctx_t *ctx);
void destroy_ratls(ratls_ctx_t *ctx);


/* Serialization Functions */
void protobuf_pack_keycert(key_cert_t *keycert, Keycert *kc);
void protobuf_free_packed_keycert(Keycert *kc);
void protobuf_unpack_keycert(key_cert_t *keycert, Keycert *kc);

#endif
