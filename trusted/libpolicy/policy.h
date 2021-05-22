#ifndef __POLICY_H__
#define __POLICY_H__

typedef struct {
    char **policies;
    int len;
} policy_ctx_t;

char *generate_action(const char *op, const char *resource, const char *user, char *buf, size_t len);
int validate_action(policy_ctx_t *p, const char *op, const char *resource, const char *user);

#endif
