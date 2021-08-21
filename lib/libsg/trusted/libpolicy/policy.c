#include <string.h>

#include "policy.h"
#include "policy_util.h"

/* 0 on success, 1 on error */
int bind_user(sg_ctx_t *ctx, const login_t *login) {
  int ret;
  char *password;
  size_t password_len;
  char *cred_key;

  cred_key = gen_resource_key(CREDENTIAL, login->user, NULL);

  ret = get_sg(ctx, cred_key, (void **)&password, &password_len);
  if (ret) {
    free(cred_key);
    return USER_NOEXIST;
  }

  // TODO: FIX THIS SO ITS NOT IN PLAIN TEXT

  ret = strcmp(login->password, password);
  if (ret) {
    ret = AUTH_FAILED;
  }

  free(cred_key);
  return ret;
}

static int auth_verify_valid(int action, sg_ctx_t *ctx, const login_t *login, const char *key) {
  int ret;

  /* Authenticate user */
  ret = bind_user(ctx, login);
  if (ret) {
    return ret;
  }

  /* Verify key */
  ret = verify_key_chars(key);
  if (ret) {
    return INVALID_KEY;
  }

  /* Validate action against policy */
  ret = check_against_policy(login->user, key, PUT);
  if (ret) {
    return ret;
  }

  return 0;
}

/* 0 on succes, 1 on error */
int put(sg_ctx_t *ctx, const login_t *login, const char *key, void *value, size_t len) {
 
  /* Authenticate user, verify key, validate action */
  int ret = auth_verify_valid(PUT, ctx, login, key);
  if (ret) {
    return ret;
  }

  /* Do the action */
  ret = put_sg(ctx, key, value, len);
  return ret;
}

int get(sg_ctx_t *ctx, const login_t *login, const char *key, void **value, size_t *len) {

   /* Authenticate user, verify key, validate action */
  int ret = auth_verify_valid(GET, ctx, login, key);
  if (ret) {
    return ret;
  }

  /* Do the action */
  ret = get_sg(ctx, key, value, len);
  return ret;
}
