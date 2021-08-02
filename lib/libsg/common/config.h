#ifndef __CONFIG_H__
#define __CONFIG_H__

#define MAX_NODES 5


/* Structure is used by both app and enclave */
typedef struct {
  int expected_ips;
  int found_ips;
  char *ips[MAX_NODES];
} configuration;

// Used by both App and Enclave
configuration *deserialize_config(const char *config, size_t config_len);

#ifdef __APP__
//configuration *deserialize_config(const char *config, size_t config_len);
char *serialize_config(configuration *config, size_t *len);
configuration *parse_config(const char *path);
int verify_config(configuration *config);
void destroy_config(configuration *config);
void prettyprint_config(configuration *config);

#endif /*__APP__ */

#endif /* __CONFIG_H__ */

