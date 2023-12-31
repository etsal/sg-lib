#ifndef __POLICY_DEFS_H__
#define __POLICY_DEFS_H__

#define POLICY_PREFIX       "policy:"
#define CREDENTIALS_PREFIX  "cred:"
#define DEFAULT_PREFIX      "home:"

typedef enum { POLICY, CREDENTIAL, DEFAULT } resource_type;
typedef enum { GET, PUT, MODIFY, DELETE } action_type;

#define USERNAME_MAX 64
#define PASSWORD_MAX 64

typedef struct {
  char user[USERNAME_MAX];
  char password[PASSWORD_MAX];
  uint32_t uid;
  // uint32_t gid;
  // uint64_t change;
  // char * class;
  // char * gecos;
  // char *dir;
  // char *shell;
  // uint64_t expire;
  // int fields;
} login_t;


#endif
