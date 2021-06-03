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

int connect_cluster_sg(sg_ctx_t *ctx);
void leave_cluster_sg();


int add_sg(sg_ctx_t *ctx, uint64_t key, const void *value, size_t len);
int find_sg(sg_ctx_t *ctx, uint64_t key, void *value, size_t len);
int remove_sg(sg_ctx_t *ctx, uint64_t key);
int count_sg(sg_ctx_t *ctx);
int save_sg(sg_ctx_t *ctx, const char *filename);
int load_sg(sg_ctx_t *ctx, const char *filename);
void print_sg(sg_ctx_t *ctx, void(*format)(const void *data));
int listen_updates_sg(sg_ctx_t *ctx);
int send_update_sg(sg_ctx_t *ctx, const char *host);

/* Where functions go to die ...
void start_server_sg(sg_ctx_t *ctx);
*/

// Private functions
void init_connections_sg(sg_ctx_t *ctx);


#endif
