#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stddef.h>
#include "sg_defs.h"

/* Structure is used by both app and enclave */
typedef struct {
  char *sealed_sg_ctx_file;
  char *log_file;
  int expected_ips;
  int found_ips;
  char *ips[MAX_NODES];
} configuration;

/* using protobufs */
configuration *unpack_config(void *buf, size_t len);
void *pack_config(configuration *config, size_t *out_len);
int verify_config(configuration *config);

// Used by both App and Enclave
configuration *deserialize_config(const char *config, size_t config_len);

#ifdef __APP__
//configuration *deserialize_config(const char *config, size_t config_len);
char *serialize_config(configuration *config, size_t *len);
configuration *parse_config(const char *path);
void destroy_config(configuration *config);
void prettyprint_config(configuration *config);

#endif /*__APP__ */

#endif /* __CONFIG_H__ */

