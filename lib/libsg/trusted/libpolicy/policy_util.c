#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "policy_util.h"
#include "policy_defs.h"
#include "policy_errlist.h"

#include "tiny-regex-c/re.h"
#include "sg.h"

//#define DEBUG_POLICY_UTIL 1
#ifdef DEBUG_POLICY_UTIL
#include "sg_common.h"
#endif



/* Remember: C automatically concats two string if they appear without anything in between? */
const char *defaults[] = {
  POLICY_PREFIX"%s/g---\n",   // User can get their own policy file
  CREDENTIALS_PREFIX"%s/gp--\n",     // User can get and modify their own cred file 
  DEFAULT_PREFIX"%s:.*/gpmd\n"   // User can get, put, modify, and delete their own home dir file
  DEFAULT_PREFIX".*/g---\n"       // User can get the files of all other user's home dir (and beyond)
};

/* Verifies that the key does not contain a disallowed character
 * 0 on success, 1 on error 
 */
int verify_key_chars(const char *key) {
  int match_length;
  if (key == NULL)
    return INVALID_KEY;
  re_t pattern = re_compile("[:/<>]"); // TODO: more programmatic way
  int match_idx = re_matchp(pattern, key, &match_length);
  if (match_idx == -1) {
    return INVALID_KEY;
  }
  return 0;
}

/* Attempts to match the access_string against an existing policy
 * return 0 on success, >0 on error
 */
int check_against_policy(sg_ctx_t *ctx, const char *user, const char *resource_key,
                                int action) {
  int ret;
  const char *value;
  size_t value_len;

#ifdef DEBUG_POLICY_UTIL
  eprintf("\t+ (%s) start\n" , __FUNCTION__);
#endif

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

  memcpy(access+len, action_perm, strlen(action_perm));
  len += strlen(action_perm);

  access[len++] = '\0';

  // Get the policies (by looking up policy_key)
  ret = get_sg(ctx, policy_key, (void *)&value, &value_len);
  if (ret) {
    free(policy_key);
    return NOEXIST_POLICY;
  }

  char *policies = malloc(strlen(value)+1);
  memcpy(policies, value, strlen(value)+1);

#ifdef DEBUG_POLICY_UTIL
    eprintf("\t\t+ (%s) key '%s' value '%s'\n", __FUNCTION__, policy_key, value); 
#endif

  // Iterate through policies (newline delimited)
  char *policy = strtok(policies, "\n");
  while (policy != NULL) {

#ifdef DEBUG_POLICY_UTIL
    eprintf("\t\t+ (%s) Found policy '%s'\n", __FUNCTION__, policy);
#endif

    // Check the action against each policy
    int match_len;
    ret = re_match(policy, access, &match_len);
    if (ret != -1) {
      ret = 0;
#ifdef DEBUG_POLICY_UTIL
    eprintf("\t\t+ (%s) Matched resource '%s' against policy '%s'\n", __FUNCTION__, access, policy);
#endif
      break; // Break we found a match

    }
    policy = strtok(NULL, "\n");
  }

  if (ret == -1) {
    ret = ACTION_NOPERM_POLICY;
#ifdef DEBUG_POLICY_UTIL
    eprintf("\t\t+ (%s) Failed to find policy in '%s' for resource '%s'\n", __FUNCTION__, policy_key, access);
#endif

  }

  free(policies);
  free(policy_key);
  return ret;
}

/* Generates the correct key in order to preform the desired operation
 * allocates memory
 * TODO: remove DEFAULT it is user's responsibility to provide correct
 * TODO: avoid mallocing here
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
    if (!verify_key_chars(key)) {
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

  if (type == DEFAULT) {
    strncpy(buf + sofar, key, strlen(key));
    sofar += strlen(key);
  }

  buf[sofar++] = '\0';

#ifdef DEBUG_POLICY_UTIL
//  eprintf("\t\t+ (%s) resource key: '%s'\n", __FUNCTION__, buf);
#endif

  return buf;
}


/* Allocates memory
 * Generates default policy for <user>
 */
char *gen_default_user_policy(const char *user) {


  int user_len = strlen(user);
  int num_defaults = sizeof(defaults) / sizeof(char *);

  char *buf;
  int i, len = 0;

  int *which = malloc(num_defaults * sizeof(int));
  memset(which, 0, num_defaults * sizeof(int));

  // Roughly get an estimate of policy buf size
  for (i=0; i<num_defaults; ++i) {
    int match_len;
    int ret = re_match("%s", defaults[i], &match_len);
    if (ret != -1) {
      len += user_len;
      which[i] = 1;
    }
    len += strlen(defaults[i]);
  }
  len += 1;
  buf = malloc(len * sizeof(char));
  
  // Generate default policies for user
  int sofar = 0;
  for (i=0; i<num_defaults; ++i) {
    if (which[i] == 1) {
      snprintf(buf+sofar, len-sofar, defaults[i], user);
      sofar += strlen(defaults[i]) - 2 + user_len; // Subtract 2 for the %s
    } else {
      snprintf(buf+sofar, len-sofar, defaults[i]);
      sofar += strlen(defaults[i]);
    }
  }
  free(which);
  assert(sofar < len);

  buf[sofar] = '\0';

#ifdef DEBUG_POLICY_UTIL
//  eprintf("\t\t+ (%s) Policy created : '%s'\n", __FUNCTION__, buf);
#endif

  return buf;
}


// char *generate_action(const char *op, const char *resource, const char *user,
// char *buf, size_t len); int validate_action(policy_ctx_t *p, const char *op,
// const char *resource, const char *user);
