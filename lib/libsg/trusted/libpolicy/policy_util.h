#ifndef __POLICY_UTIL_H__
#define __POLICY_UTIL_H__

int verify_key_chars(const char *key);

char *gen_resource_key(int type, const char *user, const char *key);

int check_against_policy(const char *user, const char *resource_key,
                                int action);

 

#endif
