#include <string.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "db.h"
#include "sg_auth.h"
#include "sg_common.h"
#include "errlist.h"

#define DEBUG_SG 1
/*
#include "sg.h"

#define SALT_SIZE 32
#define HASHED_PW_SIZE 32
*/

struct sg_passwd {
  sgx_sha256_hash_t hash; // uint8_t [SGX_SHA256_HASH_SIZE]
  uint8_t salt[SALT_SIZE];
};

static void print_sg_passwd(struct sg_passwd *p) {
  eprintf("hash : %s\n", hexstring(p->hash, sizeof(sgx_sha256_hash_t)));
  eprintf("salt : %s\n", hexstring(p->salt, SALT_SIZE));
}

int add_user_sg(sg_ctx_t *ctx, const char *username, const char *password) {
  struct sg_passwd passwd;
  sgx_status_t status;
  int ret;

  char *buf = malloc(SALT_SIZE + strlen(password) + 1);
  size_t buf_len = SALT_SIZE + strlen(password) + 1;

  // Generate random salt
  status = sgx_read_rand(passwd.salt, SALT_SIZE);
  if (status) {
    memset(passwd.salt, 0, SALT_SIZE);
  }

#ifdef DEBUG_SG
  eprintf("%s Salt generated\n", __FUNCTION__);
#endif

  // Concatenate P = salt+password
  memcpy(buf, passwd.salt, SALT_SIZE);
  memcpy(buf + SALT_SIZE, password, strlen(password));
  buf[buf_len - 1] = '\0';

  // Compute hash SHA256(P)
  status = sgx_sha256_msg(buf, buf_len, &passwd.hash);
  if (status) {
    // memset(passwd.hash, 0, SGX_SHA256_HASH_SIZE);
    memset(buf, 0, buf_len);
    return ER_SDK;
  }

#ifdef DEBUG_SG
  eprintf("%s Hash computed\n", __FUNCTION__);
  print_sg_passwd(&passwd);
#endif

  ret = put_db(&ctx->db, username, &passwd, sizeof(passwd));
#ifdef DEBUG_SG
  eprintf("%s : Put ... %s\n", __FUNCTION__, ret ? "ERROR" : "SUCCESS");
#endif
  if (ret) {
    memset(buf, 0, buf_len);
    return 1;
  }

  return 0;
}

int auth_user_sg(sg_ctx_t *ctx, const char *username, const char *password) {
  /* 1. Lookup username in db
   * 2. Grab salt from entry
   * 3. Compute P = sha256(salt+password)
   * 4. Verify P is in database
   */
  struct sg_passwd *passwd;
  size_t passwd_len;
  sgx_sha256_hash_t hash;
  sgx_status_t status;
  int ret;

  char *buf = malloc(SALT_SIZE + strlen(password) + 1);
  size_t buf_len = SALT_SIZE + strlen(password) + 1;

  ret = get_db(&ctx->db, username, (void **) &passwd, &passwd_len);
  if (!ret) {
    free(buf);
    eprintf("get_db failed!\n");
    return 1;
  }

#ifdef DEBUG_SG
  print_sg_passwd(passwd);
#endif

  // Concatenate P = salt+password
  memcpy(buf, passwd->salt, SALT_SIZE);
  memcpy(buf + SALT_SIZE, password, strlen(password));
  buf[buf_len - 1] = '\0';

  // Compute hash SHA256(P)
  status = sgx_sha256_msg(buf, buf_len, &hash);
  if (status) {
    // memset(passwd.hash, 0, SGX_SHA256_HASH_SIZE);
    memset(buf, 0, buf_len);
    return ER_SDK;
  }

  ret = memcmp(&hash, &passwd->hash, sizeof(sgx_sha256_hash_t));
  return ret;
}

