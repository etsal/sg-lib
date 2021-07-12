#ifndef __SG_AUTH_H__
#define __SG_AUTH_H__

#include "sg.h"

#define SALT_SIZE 32
#define HASHED_PW_SIZE 32

/*

int add_user_sg(sg_ctx_t *ctx, const char *username, const char *password);
int auth_user_sg(sg_ctx_t *ctx, const char *username, const char *password); 

*/

#endif

/*
struct sg_passwd {
  sgx_sha256_hash_t hash; //uint8_t [SGX_SHA256_HASH_SIZE]
  uint8_t salt[SALT_SIZE];
};
*/
