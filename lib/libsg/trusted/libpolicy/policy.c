#include <string.h>

#include "policy.h"
#include "policy_defs.h"
#include "policy_util.h"
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
void init_sg_with_policy(sg_ctx_t *ctx) {
  login_t login;
  const char *cred_key = CREDENTIALS_PREFIX "admin";
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
  const char *policy_key = POLICY_PREFIX "admin";
  ret = put_sg(ctx, policy_key, admin_policy, strlen(admin_policy) + 1);
  assert(ret == 0);

#ifdef DEBUG_POLICY
//  eprintf("\t+ (%s) Done\n", __FUNCTION__);
#endif

  return;
}

/* create_login: allocates login_t structure and populates it
 * @param user
 * @param password
 */
login_t *create_login(const char *user, const char *password) {

  if (strlen(user) + 1 > USERNAME_MAX || strlen(password) + 1 > PASSWORD_MAX) {
    return NULL;
  }

  login_t *login = malloc(sizeof(login_t));

  memcpy(login->user, user, strlen(user) + 1);
  memcpy(login->password, password, strlen(password) + 1);

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
  // eprintf("\t+ (%s) %s =? %s\n", __FUNCTION__, login->password,
  // saved->password);
#endif

  ret = strcmp(login->password, saved->password);
  if (ret) {
    ret = AUTH_FAILED;
  }

  free(saved);
  free(cred_key);
  return ret;
}


int auth_user(sg_ctx_t *ctx, const login_t *actor) {
  return bind_user(ctx, actor);
}

static int auth_verify_valid(int action, sg_ctx_t *ctx, const login_t *login,
                             const char *key) {
  int ret;

  /* Authenticate user */
  ret = bind_user(ctx, login);
  if (ret) {
    return ret;
  }

#ifdef DEBUG_POLICY
  eprintf("+ (%s) Authenticated user %s against kv-store\n", __FUNCTION__, login->user);
#endif

  /* Verify key */
  ret = verify_key_chars(key);
  if (ret) {
    return INVALID_KEY;
  }

#ifdef DEBUG_POLICY
  eprintf("+ (%s) Key %s is valid\n", __FUNCTION__, key);
#endif

  /* Validate action against policy */
  ret = check_against_policy(ctx, login->user, key, action);
#ifdef DEBUG_POLICY
  char *action_str;
  switch(action) {
    case GET:
      action_str = "GET";
      break;
    case PUT:
      action_str = "PUT";
      break;
    case MODIFY:
      action_str = "MODIFY";
      break;
    case DELETE:
      action_str = "DELETE";
      break;
  }
  eprintf("+ (%s) User %s %s %s on %s\n", __FUNCTION__, login->user, ret?"FORBIDDEN":"ALLOWED", action_str, key);
#endif
  if (ret) {
    return ret;
  }


  return 0;
}

/* 0 on success, 1 on error */
int put(sg_ctx_t *ctx, const login_t *login, const char *key, const void *value,
        size_t len) {

  /* Authenticate user, verify key, validate action */
  int ret = auth_verify_valid(PUT, ctx, login, key);
  if (ret) {
    return ret;
  }

  /* Do the action */
#ifdef DEBUG_POLICY
//  eprintf("+ (%s) Putting key '%s' value '%s' len %d\n", __FUNCTION__, key,
//          value, len);
#endif
  ret = put_sg(ctx, key, value, len);
  if (ret) {

  }

  return ret;
}

/* Allocates memory for value */
int get(sg_ctx_t *ctx, const login_t *login, const char *key, void **value,
        size_t *len) {

  /* Authenticate user, verify key, validate action */
  int ret = auth_verify_valid(GET, ctx, login, key);
  if (ret) {
    return ret;
  }

  /* Do the action */
  ret = get_sg(ctx, key, value, len);
  if (ret) {
    return NOEXIST_POLICY;
  }
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

  /* TODO: if put_policy fails then we must remove user's login OR
   * we can insert a default policy when we encounter a NO_EXIST_POLICY error in
   * another function OR we can lock the db and preform all or nothing <- THIS
   */

#ifdef DEBUG_POLICY
//  eprintf("+ (%s) complete with ret = %d\n", __FUNCTION__, ret);
#endif
  return ret;
}

/* Allocates memory for user */
int get_user(sg_ctx_t *ctx, const login_t *actor, const char *user_str,
             login_t **user) {

  size_t len;
  char *resource = gen_resource_key(CREDENTIAL, user_str, NULL);
  int ret = get(ctx, actor, resource, (void **)user, &len);
  free(resource);

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
int put_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user,
               const char *policy) {
  char *resource = gen_resource_key(POLICY, user->user, NULL);
  int ret = put(ctx, actor, resource, policy, strlen(policy) + 1);
  free(resource);

#ifdef DEBUG_POLICY
//  eprintf("+ (%s) complete with ret = %d\n", __FUNCTION__, ret);
#endif

  return ret;
}

/* Gets, appends to the policy, and stores it */
int append_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user,
                  const char *policy) {

  char *policies;
  int sofar = 0;
  int ret = get_policy(ctx, actor, user, &policies);

  if (ret) {
    return ret;
  }

  char *buf = malloc(strlen(policies) + strlen(policy) + 1);
  memcpy(buf, policies, strlen(policies));
  sofar += strlen(policies);
  memcpy(buf + sofar, policy, strlen(policy));
  sofar += strlen(policy);
  buf[sofar++] = '\0';

  free(policies);
  ret = put_policy(ctx, actor, user, buf);

  free(buf);
  return ret;
}

/* Authenticates as actor and gets the policy of user
 * returns 0 on success, and 1 on error
 */
int get_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user,
               char **policy) {
  size_t len;
  char *resource = gen_resource_key(POLICY, user->user, NULL);
  int ret = get(ctx, actor, resource, (void **)policy, &len);

  free(resource);

#ifdef DEBUG_POLICY
//  eprintf("+ (%s) complete with ret = %d\n", __FUNCTION__, ret);
#endif

  return ret;
}

