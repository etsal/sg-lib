#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "policy_util.h"
#include "policy_defs.h"
#include "policy_errlist.h"

#include "tiny-regex-c/re.h"
#include "sg.h"

//TODO dont extern, pass as arg
extern sg_ctx_t *ctx;


/* Verifies that the key does not contain a disallowed character
 * 0 on success, 1 on error 
 */
int verify_key_chars(const char *key) {
  int match_length;
  if (key == NULL)
    return 1;
  re_t pattern = re_compile("[:/<>]"); // TODO: more programmatic way
  int match_idx = re_matchp(pattern, key, &match_length);
  if (match_idx == -1) {
    return 1;
  }
  return 0;
}

/* Attempts to match the access_string against an existing policy
 * return 0 on success, >0 on error
 */
int check_against_policy(const char *user, const char *resource_key,
                                int action) {
  int ret;
  const char *value;
  size_t value_len;

  // Generate the key we will use to lookup the policies (p:<user>)
  char *policy_key = gen_resource_key(POLICY, user, NULL);

  // Generate the permission the action requires
  char *action_perm;
  switch (action) {
  case GET:
    action_perm = "g---";
    break;
  case PUT:
    action_perm = "-p--";
    break;
  case MODIFY:
    action_perm = "--m-";
    break;
  case DELETE:
    action_perm = "---d";
    break;
  }

  // Generate: resource_key + '/' + action_perm
  char access[128];
  int len = strlen(resource_key) + 1 + strlen(action_perm) + 1;
  assert(len < 128);

  len = 0;
  memcpy(access, resource_key, strlen(resource_key));
  len += strlen(resource_key);

  access[len++] = '/';

  memcpy(access, action_perm, strlen(action_perm));
  len += strlen(action_perm);

  access[len++] = '\0';

  // Get the policies (by looking up policy_key)
  ret = get_sg(ctx, policy_key, (void *)&value, &value_len);
  if (ret) {
    free(policy_key);
    return NOEXIST_POLICY;
  }

  char *policies = (char *) strndup(value, strlen(value));

  // Iterate through policies (newline delimited)
  char *policy = strtok(policies, "\n");
  while (1) {
    // Check the action against each policy
    int match_len;
    ret = re_match(policy, access, &match_len);
    if (ret != -1) {
      ret = 0;
    }
    policy = strtok(NULL, "\n");
  }

  if (ret == -1) {
    ret = INVALID_ACTION;
  }

  free(policies);
  free(policy_key);
  return ret;
}

/* Generates the correct key in order to preform the desired operation
 * allocates memory
 * TODO: remove DEFAULT it is user's responsibility to provide correct
 * resource_key
 */
char *gen_resource_key(int type, const char *user, const char *key) {
  const char *prefix;
  char *buf;
  size_t len;
  unsigned int sofar;

  switch (type) {
  case POLICY:
    prefix = POLICY_PREFIX;
    break;
  case CREDENTIAL:
    prefix = CREDENTIALS_PREFIX;
    break;
  case DEFAULT:
    prefix = DEFAULT_PREFIX;
    assert(key != NULL);
    if (!verify_chars(key)) {
      return NULL;
    }
    break;
  default:
    prefix = "";
    break;
  }

  len = strlen(prefix) + strlen(user) + 1 + 1;
  if (type == DEFAULT) {
    len += strlen(key);
  }

  buf = malloc(len * sizeof(char));

  sofar = 0;
  strncpy(buf, prefix, strlen(prefix));
  sofar += strlen(prefix);

  strncpy(buf + sofar, user, strlen(user));
  sofar += strlen(user);

  buf[sofar++] = '/';

  if (type == DEFAULT) {
    strncpy(buf + sofar, key, strlen(key));
    sofar += strlen(key);
  }

  buf[sofar++] = '\0';

  return buf;
}

// char *generate_action(const char *op, const char *resource, const char *user,
// char *buf, size_t len); int validate_action(policy_ctx_t *p, const char *op,
// const char *resource, const char *user);
