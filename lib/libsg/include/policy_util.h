#ifndef __POLICY_UTIL_H__
#define __POLICY_UTIL_H__

#include "sg.h"

int verify_key_chars(const char *key);

char *gen_resource_key(int type, const char *user, const char *key);

int check_against_policy(sg_ctx_t *ctx, const char *user, const char *resource_key,
                                int action);

char *gen_default_user_policy(const char *user);


#endif
