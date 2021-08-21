#ifndef __POLICY_H__
#define __POLICY_H__


#define POLICY_PREFIX       "/policy/"
#define CREDENTIALS_PREFIX  "/cred/"
#define DEFAULT_PREFIX      "/home/"

const char disallowed_key_chars[] = {'/', ':'};

typedef enum { POLICY_KEY, CREDENTIALS_KEY, DEFAULT_KEY } key_namespace_type;

typedef struct {
    char **policies;
    int len;
} policy_ctx_t;

/* Verifies that the key does not contain a disallowed character */
static int verify_basic_key(const char *key);

/* Generates the correct key in order to preform the desired operation 
 * allocates memory
 */
char *gen_namespace_key(const char *key, key_namespace_type type /*user*/) {
  const char *prefix;
  const char *buf;
  size_t len;
  unsigned int sofar;

  switch (type) {
  case POLICY_KEY:
    prefix = POLICY_PREFIX; 
    break;
  case CREDENTIALS_KEY:
    prefix = CREDENTIALS_PREFIX;
    break;
  case DEFAULT_KEY:
    prefix = DEFAULT_PREFIX;
    break;
  default:
    prefix = "";
    break;
  }


  len = strlen(prefix) + strlen(user) + 1 + strlen(key) + 1;  
  buf = malloc(len * sizeof(char));
  
  sofar = 0;
  strncpy(buf, prefix, strlen(prefix));
  sofar += strlen(prefix);
  strncpy(buf+sofar, user, strlen(user));
  sofar += strlen(user);
  buf[sofar++] = "/";
  strncpy(buf+sofar, key, strlen(key));
  buf[sofar++] = '\0';
 
  return buf;
}

//char *generate_action(const char *op, const char *resource, const char *user, char *buf, size_t len);
//int validate_action(policy_ctx_t *p, const char *op, const char *resource, const char *user);

void load_policy();

#endif
