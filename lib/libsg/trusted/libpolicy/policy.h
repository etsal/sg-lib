#ifndef __POLICY_H__
#define __POLICY_H__

#include "policy_errlist.h"

#define POLICY_PREFIX       "/policy/"
#define CREDENTIALS_PREFIX  "/cred/"
#define DEFAULT_PREFIX      "/home/"

typedef enum { POLICY, CREDENTIAL, DEFAULT } resource_type;
typedef enum { GET, PUT, MODIFY, DELETE } action_type;

// Initializes ctx
void init();

int put_policy();
int get_policy();

int put_creds();
int get_creds();

// Admin functions
int auth_user();




//char *generate_action(const char *op, const char *resource, const char *user, char *buf, size_t len);
//int validate_action(policy_ctx_t *p, const char *op, const char *resource, const char *user);

#endif
