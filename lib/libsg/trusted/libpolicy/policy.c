#include <string.h>

#include "policy.h"
#include "policy_util.h"
#include "policy_defs.h"
#include "tiny-regex-c/re.h"

#define DEBUG_POLICY 1
#ifdef DEBUG_POLICY
#include "sg_common.h"
#endif

const char admin_policy[] = ".*\n";

/* Initializes the kvstore with admin entries
 * policies
 * With user=admin, password=admin
 */
void init_new_policy(sg_ctx_t *ctx) {
  login_t login;
  const char *cred_key = CREDENTIALS_PREFIX"admin";
  login_t *value = create_login("admin", "admin");
  assert(value != NULL);

#ifdef DEBUG_POLICY
//  eprintf("\t+ (%s) Initializing new sg\n", __FUNCTION__);
#endif

  init_new_sg(ctx);

#ifdef DEBUG_POLICY
//  eprintf("\t+ (%s) Putting admin credentials\n", __FUNCTION__);
#endif

  // Add admin credentials
  int ret = put_sg(ctx, cred_key, (void *)value, sizeof(login_t));
  free(value);
  assert(ret == 0);

#ifdef DEBUG_POLICY
//  eprintf("\t+ (%s) Putting admin policies\n", __FUNCTION__);
#endif

  // Admin's policy
  const char *policy_key = POLICY_PREFIX"admin";
  ret = put_sg(ctx, policy_key, admin_policy, strlen(admin_policy)+1);
  assert(ret == 0);

#ifdef DEBUG_POLICY
//  eprintf("\t+ (%s) Done\n", __FUNCTION__);
#endif

  return; 
}

login_t *create_login(const char *user, const char *password) {
  
  if (strlen(user)+1 > USERNAME_MAX ||
      strlen(password)+1 > PASSWORD_MAX) {
    return NULL;
  }

  login_t *login = malloc(sizeof(login_t));

  memcpy(login->user, user, strlen(user)+1);
  memcpy(login->password, password, strlen(password)+1);

  return login;
}

/* 0 on success, 1 on error */
int bind_user(sg_ctx_t *ctx, const login_t *login) {
  int ret;
  login_t *saved;
  size_t len;
  char *cred_key;

  cred_key = gen_resource_key(CREDENTIAL, login->user, NULL);

  ret = get_sg(ctx, cred_key, (void **)&saved, &len);
  if (ret) {
    free(cred_key);
    return USER_NOEXIST;
  }

  // TODO: FIX THIS SO ITS NOT IN PLAIN TEXT

#ifdef DEBUG_POLICY
  //eprintf("\t+ (%s) %s =? %s\n", __FUNCTION__, login->password, saved->password);
#endif

  ret = strcmp(login->password, saved->password);
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
  ret = check_against_policy(ctx, login->user, key, PUT);
  if (ret) {
    return ret;
  }

  return 0;
}

/* 0 on succes, 1 on error */
int put(sg_ctx_t *ctx, const login_t *login, const char *key, const void *value, size_t len) {
 
  /* Authenticate user, verify key, validate action */
  int ret = auth_verify_valid(PUT, ctx, login, key);
  if (ret) {
    return ret;
  }

  /* Do the action */
#ifdef DEBUG_POLICY
  eprintf("\t\t+ (%s) Putting key '%s' value '%s' len %d\n", __FUNCTION__, key, value, len);
#endif

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

/*
 * Wrapper for put that only puts users
 * Authenticates as actor
 * installs new user
 * then install policies for user
 */
int put_user(sg_ctx_t *ctx, const login_t *actor, const login_t *new_user) {

  char *resource = gen_resource_key(CREDENTIAL, new_user->user, NULL);
  int ret = put(ctx, actor, resource, new_user, sizeof(login_t));
  free(resource);
  if (ret) {
    return ret;
  }

  char *policy = gen_default_user_policy(new_user->user);
  if (policy == NULL) {
    return ret;
  }

  ret = put_policy(ctx, actor, new_user, policy);
  free(policy);

#ifdef DEBUG_POLICY
  eprintf("+ (%s) complete with ret = %d\n", __FUNCTION__, ret);
#endif


  return ret;
}

/*
 * Wrapper for sg that only puts policy
 * authenitcates as actor
 * installs policy for user
*/
int put_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user, const char *policy) {
  char *resource = gen_resource_key(POLICY, user->user, NULL);
  int ret = put(ctx, actor, resource, policy, strlen(policy)+1);
  free(resource);

#ifdef DEBUG_POLICY
  eprintf("+ (%s) complete with ret = %d\n", __FUNCTION__, ret);
#endif

  return ret;
}




