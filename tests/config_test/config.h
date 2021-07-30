#ifndef __CONFIG_H__
#define __CONFIG_H__

#define MAX_NODES 5

typedef struct {
  int expected_ips;
  int found_ips;
  char *ips[MAX_NODES];
} configuration;

configuration *parse_config(const char *path);
void prettyprint_configuration(configuration *config);

#endif

