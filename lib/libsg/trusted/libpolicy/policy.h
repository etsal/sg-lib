#ifndef __POLICY_H__
#define __POLICY_H__

#include "sg.h"
//#include "config.h"
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
void init_sg_with_policy(sg_ctx_t *ctx, void *config, size_t config_len); // Calls sg_new_init

int put(sg_ctx_t *ctx, const login_t *login, const char *key, const void *value, size_t len);
int get(sg_ctx_t *ctx, const login_t *login, const char *key, void **value, size_t *len);
//int search(sg_ctx_t *ctx, const login_t *login, const char *regex, char **value, void **value, size_t *len);

/* Appends to the policy file */
int put_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user, const char *policy);
int get_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user, char **policy);
int append_policy(sg_ctx_t *ctx, const login_t *actor, const login_t *user, const char *policy);

/* User functions
 * put_user : Only root can add a user
 * get_user : Anyone can search for a user 
 * auth_user : Authenticates user against store
 * */
int put_user(sg_ctx_t *ctx, const login_t *actor, login_t *new_user);
int auth_user(sg_ctx_t *ctx, const login_t *actor);
int get_user_by_name(sg_ctx_t *ctx, const char *name, login_t **user);
int get_user_by_id(sg_ctx_t *ctx, uint32_t uid, login_t **user);

login_t *create_login(sg_ctx_t *ctx, const char *user, const char *password);

// Admin functions
//int auth_user();

#endif
