#include "sgx_trts.h"

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#include "sg_t.h" // For boundary calls
#include "sg_defs.h"

#define WOLFTLSv12_CLIENT 1
#define WOLFTLSv12_SERVER 2

#define MAX_WOLFSSL_CTX MAX_NODES+1
#define MAX_WOLFSSL MAX_NODES+1 // Max number of WOLFSSL's

WOLFSSL_CTX* CTX_TABLE[MAX_WOLFSSL_CTX];
WOLFSSL* SSL_TABLE[MAX_WOLFSSL];

/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
static long AddCTX(WOLFSSL_CTX* ctx) {
    long i;
    for (i = 0; i < MAX_WOLFSSL_CTX; i++) {
         if (CTX_TABLE[i] == NULL) {
             CTX_TABLE[i] = ctx;
             return i;
         }
    }
    return -1;
}

/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
static long AddSSL(WOLFSSL* ssl) {
    long i;
    for (i = 0; i < MAX_WOLFSSL; i++) {
         if (SSL_TABLE[i] == NULL) {
             SSL_TABLE[i] = ssl;
             return i;
         }
    }
    return -1;
}


/* returns the WOLFSSL_CTX pointer on success and NULL on failure */
static WOLFSSL_CTX* GetCTX(long id) {
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return NULL;
    return CTX_TABLE[id];
}


/* returns the WOLFSSL pointer on success and NULL on failure */
static WOLFSSL* GetSSL(long id) {
    if (id >= MAX_WOLFSSL || id < 0)
        return NULL;
    return SSL_TABLE[id];
}


/* Free's and removes the WOLFSSL_CTX associated with 'id' */
static void RemoveCTX(long id) {
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return;
    wolfSSL_CTX_free(CTX_TABLE[id]);
    CTX_TABLE[id] = NULL;
}

/* Free's and removes the WOLFSSL associated with 'id' */
static void RemoveSSL(long id)
{
    if (id >= MAX_WOLFSSL || id < 0)
        return;
    wolfSSL_free(SSL_TABLE[id]);
    SSL_TABLE[id] = NULL;
}

void enc_wolfSSL_Debugging_ON(void) {
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void) {
    wolfSSL_Debugging_OFF();
}

int enc_wolfSSL_Init(void) {
    return wolfSSL_Init();
}

long enc_wolfTLSv1_2_client_method(void) {
    return WOLFTLSv12_CLIENT;
}

long enc_wolfTLSv1_2_server_method(void) {
    return WOLFTLSv12_SERVER;
}

/* returns method releated to id */
static WOLFSSL_METHOD* GetMethod(long id) {
    switch (id) {
        case WOLFTLSv12_CLIENT: return wolfTLSv1_2_client_method();
        case WOLFTLSv12_SERVER: return wolfTLSv1_2_server_method();
        default:
            return NULL;
    }
}

long enc_wolfSSL_CTX_new(long method) {
    WOLFSSL_CTX* ctx;
    long id = -1;

    ctx = wolfSSL_CTX_new(GetMethod(method));
    if (ctx != NULL) {
        id = AddCTX(ctx);
    }
    return id;
}

int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(long id,
        const unsigned char* buf, long sz, int type) {
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_certificate_buffer(long id,
        const unsigned char* buf, long sz, int type) {
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_use_certificate_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_PrivateKey_buffer(long id, const unsigned char* buf,
                                            long sz, int type) {
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_load_verify_buffer(long id, const unsigned char* in,
                                       long sz, int format) {
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_load_verify_buffer(ctx, in, sz, format);
}

// NEW
int enc_wolfSSL_CTX_set_verify(long id, int flags, VerifyCallback verify_callback) {
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    wolfSSL_CTX_set_verify(ctx, flags, verify_callback);
    return SSL_SUCCESS;
}

// NEW
int enc_wolfSSL_negotiate(long sslId) {
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_negotiate(ssl);
}

// NEW
WOLFSSL_X509 *enc_wolfSSL_get_peer_certificate(long sslId) {
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return NULL;
    }
    return wolfSSL_get_peer_certificate(ssl);
}

int enc_wolfSSL_CTX_set_cipher_list(long id, const char* list) {
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_set_cipher_list(ctx, list);
}

long enc_wolfSSL_new(long id) {
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    long ret = -1;

    ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    ssl = wolfSSL_new(ctx);
    if (ssl != NULL) {
        ret = AddSSL(ssl);
    }
    return ret;
}

int enc_wolfSSL_set_fd(long sslId, int fd) {
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_set_fd(ssl, fd);
}

int enc_wolfSSL_connect(long sslId) {
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_connect(ssl);
}

int enc_wolfSSL_write(long sslId, const void* in, int sz) {
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_write(ssl, in, sz);
}

int enc_wolfSSL_get_error(long sslId, int ret) {
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_get_error(ssl, ret);
}

int enc_wolfSSL_read(long sslId, void* data, int sz) {
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_read(ssl, data, sz);
}

void enc_wolfSSL_free(long sslId) {
    RemoveSSL(sslId);
}

void enc_wolfSSL_CTX_free(long id) {
    RemoveCTX(id);
}

void enc_wolfSSL_Cleanup(void) {
    long id;

    /* free up all WOLFSSL's */
    for (id = 0; id < MAX_WOLFSSL; id++)
        RemoveSSL(id);

    /* free up all WOLFSSL_CTX's */
    for (id = 0; id < MAX_WOLFSSL_CTX; id++)
        RemoveCTX(id);
    wolfSSL_Cleanup();
}

int LowResTimer(void) {
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags) {
    size_t ret;
    int status;
    status = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags) {
    size_t ret;
    int status;
    status = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}
