#include <assert.h>

#include "attester.h"   // key_and_x509
#include "challenger.h" // get_quote_from_cert(), verify_sgx_cert_extensions()
#include "ra_tls.h"
#include "sg_common.h"
#include "sg_stdfunc.h"
#include "wolfssl_enclave.h"
/*
 * For ocalls
 */
#include "sg_t.h"

#define PORT "7777"

//#define DEBUG_RATLS 1

extern ra_tls_options_t global_opts;

static int host_bind(const char *host, const char *port) {
  int ret = -1;
  sgx_status_t status = ocall_host_bind(&ret, host, port);
  if (status != SGX_SUCCESS) {
    return -1;
  }
  return ret;
}

static int host_connect(const char *host, const char *port) {
  int ret = -1;
  sgx_status_t status = ocall_host_connect(&ret, host, port);
  if (status != SGX_SUCCESS) {
    return -1;
  }
  return ret;
}

static int accept_client(int sock_fd) {
  int ret = -1;
  sgx_status_t status = ocall_accept_client(&ret, sock_fd);
  if (status != SGX_SUCCESS) {
    return -1;
  }
  return ret;
}

static int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *store) {
  (void)preverify;
  int ret =
      verify_sgx_cert_extensions(store->certs->buffer, store->certs->length);
#ifdef DEBUG_RATLS
  eprintf("\t+ Verifying SGX certificate extenstions ... %s\n", __FUNCTION__,
          ret == 0 ? "Success" : "Failure");
#endif
  return !ret;
}

/* verify_connection
 * checks the certificates sent in RATLS negotiation
 * TODO: do the check
 * @param ctx
 * @return 1 on success, 0 on error
 */
static int verify_connection(ratls_ctx_t *ctx) {
  WOLFSSL_X509 *cert;
  int derSz;
  const unsigned char *der;
  sgx_quote_t quote;
  sgx_report_body_t *body;

  memset(&quote, 0, sizeof(sgx_quote_t));

  cert = enc_wolfSSL_get_peer_certificate(ctx->ssl);
  der = wolfSSL_X509_get_der(cert, &derSz);
  get_quote_from_cert(der, derSz, &quote);
  body = &quote.report_body;

#ifdef DEBUG_RATLS
  eprintf("\t+ %s : Checking peer's identity\n", __FUNCTION__);
  eprintf("\t  + Server's SGX identity:\n");
  eprintf("\t    . MRENCLAVE = %s\n",
          hexstring(body->mr_enclave.m, SGX_HASH_SIZE));
  eprintf("\t    . MRSIGNER  = %s\n",
          hexstring(body->mr_signer.m, SGX_HASH_SIZE));
#endif

  return 1;
}

void init_ratls() {
  int ret = enc_wolfSSL_Init();
  if (ret != SSL_SUCCESS) {
    eprintf("\t + (%s) enc_wolfSSL_Init failed\n", __FUNCTION__);
    exit(1);
  }
}

/* cleanup_ratls : Frees the wolfSSL object (ctx.ssl) and 
 * the wolfSSL context object (ctx.ctx) and closes the socket
 * (ctx.sockfd)
 * @param ctx 
 */
void cleanup_ratls(ratls_ctx_t *ctx) {
  enc_wolfSSL_free(ctx->ssl);
  enc_wolfSSL_CTX_free(ctx->ctx); 
  close(ctx->sockfd);
}



void init_ratls_server(ratls_ctx_t *server, key_cert_t *kc) {
  /* Key need to be generated with create_key_and_x509 */
  assert(kc->der_key_len > 0 && kc->der_cert_len > 0);

  /* Create a socket that uses an internet IPv4 address,
   * Sets the socket to be stream based (TCP),
   * 0 means choose the default protocol.
   */
  server->sockfd = host_bind(NULL, PORT);
  if (!(server->sockfd > 0)) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) host bind failed\n", __FUNCTION__);
#endif
    exit(1);
  }

  /* Create and initialize wolfssl context */
  server->method = enc_wolfTLSv1_2_server_method();
  server->ctx = enc_wolfSSL_CTX_new(server->method);
  if (server->ctx < 0) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) enc_wolfSSL_CTX_new\n", __FUNCTION__);
#endif
    exit(1);
  }

  /* Load server certificates into WOLFSSL_CTX */
  int ret = enc_wolfSSL_CTX_use_certificate_buffer(
      server->ctx, kc->der_cert, kc->der_cert_len, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
    eprintf("\t + (%s) enc_wolfSSL_CTX_use_certificate_chain_buffer_format "
            "failed\n",
            __FUNCTION__);
    exit(1);
  }

  /* Load server key into WOLFSSL_CTX */
  ret = enc_wolfSSL_CTX_use_PrivateKey_buffer(
      server->ctx, kc->der_key, kc->der_key_len, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
    eprintf("%s : wolfSSL_CTX_use_PrivateKey_buffer failed\n", __FUNCTION__);
    exit(1);
  }

  // NEW
  ret = enc_wolfSSL_CTX_load_verify_buffer(server->ctx, kc->der_cert,
                                           kc->der_cert_len, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
    eprintf("%s : wolfSSL_CTX_load_verify_buffer failed\n", __FUNCTION__);
    exit(1);
  }

  // NEW: Set mutual authentication
  enc_wolfSSL_CTX_set_verify(
      server->ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
      cert_verify_callback);
}

int init_ratls_client(ratls_ctx_t *client, key_cert_t *kc, const char *host) {
#ifdef DEBUG_RATLS
  eprintf("\t+ (%s) start\n", __FUNCTION__);
#endif
  // eprintf("\t+ enc_wolfTLSv1_2_client_method\n");
  client->method = enc_wolfTLSv1_2_client_method();

  // eprintf("\t+ enc_wolfSSL_CTX_new\n");
  client->ctx = enc_wolfSSL_CTX_new(client->method);
  if (client->ctx < 0) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) enc_wolfSSL_CTX_new failed\n", __FUNCTION__);
#endif
    return 1;
  }

  // eprintf("\t+ enc_wolfSSL_CTX_use_certificate_buffer\n");
  // I think this the chain isnt needed here
  int ret = enc_wolfSSL_CTX_use_certificate_buffer(
      client->ctx, kc->der_cert, kc->der_cert_len, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) enc_wolfSSL_CTX_use_certificate_buffer failed with %d\n",
            __FUNCTION__, ret);
#endif
    return 1;
  }

  // eprintf("\t+ enc_wolfSSL_CTX_use_PrivateKey_buffer\n");
  ret = enc_wolfSSL_CTX_use_PrivateKey_buffer(
      client->ctx, kc->der_key, kc->der_key_len, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) wolfSSL_CTX_use_PrivateKey_buffer failed\n");
#endif
    return 1;
  }

  /*
    ret = enc_wolfSSL_CTX_load_verify_buffer(ctx->ctx, kc->der_cert,
    kc->der_cert_len, SSL_FILETYPE_ASN1); if (ret != SSL_SUCCESS) {
        eprintf("Error loading cert\n");
        exit(1);
    }
  */
#ifdef DEBUG_RATLS
  eprintf("\t + (%s) Calling host_connect\n", __FUNCTION__);
#endif

  client->sockfd = host_connect(host, PORT);
  if (!(client->sockfd > 0)) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) host_connect failed\n", __FUNCTION__);
#endif
    return 1;
  }

  // Enable client authentication
  //    eprintf("\t+ enc_wolfSSL_CTX_set_verify\n");
  ret = enc_wolfSSL_CTX_set_verify(client->ctx, WOLFSSL_VERIFY_PEER,
                                   cert_verify_callback);
  if (ret != SSL_SUCCESS) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) enc_wolfSSL_CTX_set_verify failed\n", __FUNCTION__);
#endif
    return 1;
  }

  // Create new SSL session
  //	eprintf("\t+ enc_wolfSSL_new\n");
  client->ssl = enc_wolfSSL_new(client->ctx);
  if (client->ssl < 0) {
#ifdef DEBUG_RATLS
    eprintf("\t + %s : wolfSSL_new failed\n", __FUNCTION__);
#endif
    return 1;
  }

  // Attach wolfSSL to the socket
  ret = enc_wolfSSL_set_fd(client->ssl, client->sockfd);
  if (ret != SSL_SUCCESS) {
#ifdef DEBUG_RATLS
    eprintf("\t (%s) wolfSSL_set_fd failed\n", __FUNCTION__);
#endif
    return 1;
  }

  //    eprintf("\t+ enc_wolfSSL_connect\n");
  ret = enc_wolfSSL_connect(client->ssl);
  if (ret != SSL_SUCCESS) {
#ifdef DEBUG_RATLS
    eprintf("\t + (%s) enc_wolfSSL_connect failed\n", __FUNCTION__);
#endif
    return 1;
  }

  ret = verify_connection(client);
  if (ret) {
    ret = 0;
  } else {
    ret = 1;
  }

  return ret;
}

/* accept_cluster_connections
 * to be called by with initialized "server" to accept incoming "client"
 * replaces: listen_ratls_server
 * @param server Initialized server RA TLS context
 * @param client Empty TA TLS context, this function will populate it
 * @param sockfd Int pointer to be filled in with accepted connection
 * @return 0 on success, 1 on error
 */
int accept_cluster_connections(ratls_ctx_t *server, ratls_ctx_t *client) {
  int ret;
  WOLFSSL_X509 *client_cert;
  int derSz;
  const unsigned char *der;
  sgx_quote_t quote;
  sgx_report_body_t *body;

  /* Accept client connections */
  client->sockfd = accept_client(server->sockfd);
  if (client->sockfd == 0 || client->sockfd < 0) {
    eprintf("\t +(%s) ocall_accept_client failed\n", __FUNCTION__);
    return 1;
  }

  /* Create a WOLFSSL object */
  // Is this suppose to be server->ctx
  //client->ssl = enc_wolfSSL_new(client->ctx);
  client->ssl = enc_wolfSSL_new(server->ctx);
  if (client->ssl < 0) {
    eprintf("\t+ (%s) wolfSSL_new failed\n", __FUNCTION__);
    return 1;
  }

  /* Attach wolfSSL to the socket */
  ret = enc_wolfSSL_set_fd(client->ssl, client->sockfd);
  if (ret != SSL_SUCCESS) {
    eprintf("\t+ (%s) wolfSSL_set_fd failed\n", __FUNCTION__);
    return 1;
  }

  ret = enc_wolfSSL_negotiate(client->ssl);
  if (ret != SSL_SUCCESS) {
    eprintf("\t+ (%s) wolfSSL_negotiate failed\n", __FUNCTION__);
    return 1;
  }

#ifdef DEBUG_RATLS
  eprintf("\t+ (%s) Client connected successfully\n", __FUNCTION__);
#endif

  ret = verify_connection(client);
  if (ret) {
    ret = 0;
  } else {
    ret = 1;
  }

  return ret;
}

int read_ratls(ratls_ctx_t *ctx, uint8_t *data, size_t len) {
  int ret = enc_wolfSSL_read(ctx->ssl, data, len);
  if (ret == -1) {
    eprintf("%s : Server read failed\n", __FUNCTION__);
    exit(1);
  }
  return ret;
}

int write_ratls(ratls_ctx_t *ctx, uint8_t *data, size_t len) {
  int ret = enc_wolfSSL_write(ctx->ssl, data, len);
  if (ret != len) {
    eprintf("%s : Server write failed\n", __FUNCTION__);
    exit(1);
  }
  return ret;
}

void close_ratls_server(ratls_ctx_t *ctx) {
  enc_wolfSSL_free(ctx->ssl);
  ocall_close(NULL, ctx->sockfd); // Don't care about retval
  ctx->sockfd = 0;
}

void destroy_ratls(ratls_ctx_t *ctx) {
  enc_wolfSSL_free(ctx->ssl);     // If server this might be free already
  enc_wolfSSL_CTX_free(ctx->ctx); // Free the wolfSSL context object
  enc_wolfSSL_Cleanup();          // Cleanup the wolfSSL environment
  ocall_close(NULL, ctx->sockfd); // Close the socket listening for clients
  memset(ctx, 0, sizeof(ratls_ctx_t));
}

void protobuf_pack_keycert(key_cert_t *keycert, Keycert *kc) {
  kc->key_type = keycert->key_type;

  kc->key.len = keycert->der_key_len;
  kc->key.data = malloc(keycert->der_key_len);
  memcpy(kc->key.data, keycert->der_key, keycert->der_key_len);

  kc->cert.len = keycert->der_cert_len;
  kc->cert.data = malloc(keycert->der_cert_len);
  memcpy(kc->cert.data, keycert->der_cert, keycert->der_cert_len);
}

void protobuf_free_packed_keycert(Keycert *kc) {
  free(kc->key.data);
  free(kc->cert.data);
}

void protobuf_unpack_keycert(key_cert_t *keycert, Keycert *kc) {
  keycert->key_type = kc->key_type;

  assert(!(kc->key.len > DER_KEY_LEN));
  assert(!(kc->cert.len > DER_CERT_LEN));

  keycert->der_key_len = kc->key.len;
  memcpy(keycert->der_key, kc->key.data, kc->key.len);

  keycert->der_cert_len = kc->cert.len;
  memcpy(keycert->der_cert, kc->cert.data, kc->cert.len);
}

