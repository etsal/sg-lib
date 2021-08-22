#ifndef __POLICY_H__
#define __POLICY_H__

#include "sg.h"
#include "policy_errlist.h"
#include "policy_defs.h"
/*
#define POLICY_PREFIX       "/policy/"
#define CREDENTIALS_PREFIX  "/cred/"
#define DEFAULT_PREFIX      "/home/"

typedef enum { POLICY, CREDENTIAL, DEFAULT } resource_type;
typedef enum { GET, PUT, MODIFY, DELETE } action_type;


#define USERNAME_MAX 64
#define PASSWORD_MAX 64

typedef struct {
  char user[USERNAME_MAX];
  char password[PASSWORD_MAX];
} login_t;
*/ // Now in policy_defs.h


// Initializes ctx
void init_new_policy(sg_ctx_t *ctx); // Calls sg_new_init

int put(sg_ctx_t *ctx, const login_t *login, const char *key, const void *value, size_t len);
int get(sg_ctx_t *ctx, const login_t *login, const char *key, void **value, size_t *len);

/* Appends to the policy file */
int put_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user, const char *policy);
//int get_policy();

int put_user(sg_ctx_t *ctx, const login_t *actor, const login_t *new_user);
//int get_user();

login_t *create_login(const char *user, const char *password);

// Admin functions
//int auth_user();

//char *generate_action(const char *op, const char *resource, const char *user, char *buf, size_t len);
//int validate_action(policy_ctx_t *p, const char *op, const char *resource, const char *user);

#endif
