/*
 * <operation>:<path to resource>:<user>
 * Example:
 *  (& (add:/u2f/<user>) (<user>))
 * access to /u2f/ by <> get, put, del
 *
 *
 * put:/u2f/stef/(*):stef
 * get:/u2f/stef/(*):stef
 *
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
//#include <stdio.h>
/*
#include "policy.h"
#include "tiny-regex-c/re.h"

char *
generate_action(const char *op, const char *resource, const char *user,
    char *buf, size_t len)
{
	int action_len = strlen(op) + 1 + strlen(resource) + 1 + strlen(user) +
	    1;
	char *action = NULL, *start = NULL;

	if (buf == NULL) {
		action = malloc(action_len);
		start = action;
	} else {
		assert(len > action_len || len == action_len);
		action = buf;
		start = buf;
	}

	len = strlen(op);
	strncpy(action, op, len);
	action += len;

	len = strlen(":");
	strncpy(action, ":", len);
	action += len;

	len = strlen(resource);
	strncpy(action, resource, len);
	action += len;

	len = strlen(":");
	strncpy(action, ":", len);
	action += len;

	len = strlen(user);
	strncpy(action, user, len);
	action += len;

	len = strlen("\0");
	strncpy(action, "\0", len);
	action += len;

	return start;
}

static int
check_against_policy(const char *policy, const char *action)
{
	int ret = 0;
	const char delim[2] = ":";
	char *tmp_policy = malloc(strlen(policy) + 1);
	char *tmp_action = malloc(strlen(action) + 1);

	strncpy(tmp_policy, policy, strlen(policy) + 1);
	strncpy(tmp_action, action, strlen(action) + 1);

	char *policy_tokens[3];
	char *action_tokens[3];

	policy_tokens[0] = strtok(tmp_policy, delim);
	policy_tokens[1] = strtok(NULL, delim);
	policy_tokens[2] = strtok(NULL, delim);

	action_tokens[0] = strtok(tmp_action, delim);
	action_tokens[1] = strtok(NULL, delim);
	action_tokens[2] = strtok(NULL, delim);

	// printf("%s : \n\taction '%s' \n\tpolicy '%s'\n", __FUNCTION__,
	// action, policy);

	//   Match operation
	if (strcmp(policy_tokens[0], action_tokens[0])) {
		goto cleanup;
	}

	// Match resource identifier
	int match_len = 0;
	int match_idx = re_match(
	    policy_tokens[1], action_tokens[1], &match_len);
	if (match_idx == -1 || match_len != strlen(action_tokens[1])) {
		//      printf("regex fail: \n\tpattern %s\n\ttext
		//      %s\n\tmatch_len %d expected len %d\n", policy_tokens[1],
		//      action_tokens[1], match_len, strlen(action_tokens[1]));
		goto cleanup;
	}

	// Match user
	if (strcmp(policy_tokens[2], action_tokens[2])) {
		goto cleanup;
	}

	ret = 1;

cleanup:
	free(tmp_policy);
	free(tmp_action);
	return ret;
}

static int
validate_prepared_action(policy_ctx_t *p, const char *action)
{
	for (int i = 0; i < p->len; ++i) {
		if (check_against_policy(p->policies[i], action))
			return 1;
	}
	return 0;
}

int
validate_action(
    policy_ctx_t *p, const char *op, const char *resource, const char *user)
{
	char action[128] = { 0 };
	generate_action(op, resource, user, action, sizeof(action));
	return validate_prepared_action(p, action);
}

*/
