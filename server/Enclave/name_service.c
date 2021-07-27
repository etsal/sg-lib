#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "sg.h"
#include "sg_common.h"
#define PASSWD_SALT_SZ 32

extern sg_ctx_t sg_ctx;

struct user_info {
  uint8_t salt[PASSWD_SALT_SZ];
  sgx_sha256_hash_t hash;
};

/* 1 on error, 0 on success */
int ecall_add_user(const char *username, const char *password) {
  struct user_info info;
  sgx_status_t status;
  int ret;

  char *buf = malloc(PASSWD_SALT_SZ + strlen(password) + 1);
  size_t buf_len = PASSWD_SALT_SZ + strlen(password) + 1;

  // Generate random salt
  status = sgx_read_rand(info.salt, PASSWD_SALT_SZ);
  if (status) {
    memset(info.salt, 0, PASSWD_SALT_SZ);
  }

  // Concatenate P = salt+password
  memcpy(buf, info.salt, PASSWD_SALT_SZ);
  memcpy(buf + PASSWD_SALT_SZ, password, strlen(password));
  buf[buf_len - 1] = '\0';

  // Compute hash SHA256(P)
  status = sgx_sha256_msg(buf, buf_len, &info.hash);
  if (status) {
    // memset(&info, 0, sizeof(struct user_info));
    memset(buf, 0, buf_len);
    free(buf);
    return 1;
  }

  ret = put_sg(&sg_ctx, username, buf, buf_len);
  memset(buf, 0, buf_len);
  free(buf);

  return ret;
}

/* return 0 on success, 1 on error */
int ecall_auth_user(const char *username, const char *password) {
  struct user_info *info;
  size_t sz;
  sgx_sha256_hash_t hash;
  sgx_status_t status;
  int ret;

  char *buf = malloc(PASSWD_SALT_SZ + strlen(password) + 1);
  size_t buf_len = PASSWD_SALT_SZ + strlen(password) + 1;

  eprintf("%s : Calling get_sg\n", __FUNCTION__);

  ret = get_sg(&sg_ctx, username, (void **)&info, &sz);
  if (!ret || sz != sizeof(struct user_info)) {
    free(buf);
    return 1;
  }

  // Concatenate P = salt+password
  memcpy(buf, info->salt, PASSWD_SALT_SZ);
  memcpy(buf + PASSWD_SALT_SZ, password, strlen(password));
  buf[buf_len - 1] = '\0';

  eprintf("%s : Calling sgx_sha256_msg\n", __FUNCTION__);

// Compute hash SHA256(P)
  status = sgx_sha256_msg(buf, buf_len, &hash);
  if (status) {
    memset(buf, 0, buf_len);
    free(buf);
    return 1;
  }

  ret = memcmp(hash, info->hash, sizeof(sgx_sha256_hash_t));
  memset(buf, 0, buf_len);
  free(buf);

  eprintf("%s : memcmp returned %d\n", __FUNCTION__, ret);

  return ret;
}
