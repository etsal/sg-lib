#ifndef __SG_H__
#define __SG_H__

#include "ra_tls.h"
#include "db.h"

typedef struct {
    key_cert_t kc;      // RA-TLS Keys and Certs
    ratls_ctx_t ratls;  // RA-TLS Context (Wolfssl stuff)
    db_ctx_t db;        // Database Context
    char policy_filename[1024];
    
} sg_ctx_t;

void init_sg(sg_ctx_t *ctx);
void init_new_sg(sg_ctx_t *ctx);

int verify_connections_sg(sg_ctx_t *ctx);
int recieve_connections_sg(sg_ctx_t *ctx);
int initiate_connections_sg(sg_ctx_t *ctx);
void cleanup_connections_sg();

// Network functions. See sg_network.c
int poll_and_process_updates_sg(sg_ctx_t *ctx);

// Testing purposes
int send_msg_sg(sg_ctx_t *ctx, const char *msg);

int put_sg(sg_ctx_t *ctx, const char *key, const void *value, size_t len);
int get_sg(sg_ctx_t *ctx, const char *key, void **value, size_t *len);
int put_u64_sg(sg_ctx_t *ctx, uint64_t key, const void *value, size_t len);
int get_u64_sg(sg_ctx_t *ctx, uint64_t key, void **value, size_t *len);





int remove_sg(sg_ctx_t *ctx, uint64_t key);
int count_sg(sg_ctx_t *ctx);
int save_sg(sg_ctx_t *ctx, const char *filename);
int load_sg(sg_ctx_t *ctx, const char *filename);
void print_sg(sg_ctx_t *ctx, void(*format)(const void *data));

// Admin
int add_user_sg(sg_ctx_t *ctx, const char *username, const char *password);
int modify_password_sg(sg_ctx_t *ctx, const char *username, const char *password);

// Anyone
int auth_user_sg(sg_ctx_t *ctx, const char *username, const char *password); //Verify identitdy by checking pw
int account_user_sg(sg_ctx_t *ctx); // Check that the specified account is a valid authentication target





// Private functions
void init_connections(sg_ctx_t *ctx); // Initializes connection structures

#endif
