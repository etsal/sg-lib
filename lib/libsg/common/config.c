/* Example: parse a simple configuration file */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "config.pb-c.h"

#ifdef __APP__
#include "inih/ini.h"
#endif

#define DEBUG_SG 1


/* Used to verify that the config file stores everything we expect */
int verify_config(configuration *config) {
  return 1;
}



configuration *unpack_config(void *buf, size_t len) {
  
  Config *c = config__unpack(NULL, len, buf);

  configuration *config = malloc(sizeof(configuration));

  //memcpy(config->database_file, c->database_file, strlen(c->database_file)+1);
  config->database_file = strndup(c->database_file, strlen(c->database_file)+1);
  config->found_ips = c->n_hosts;
  config->expected_ips = c->n_hosts;

  assert(config->found_ips < MAX_NODES);

  int i;
  for (i=0; i<c->n_hosts; ++i) {
    config->ips[i] = strndup(c->hosts[i], strlen(c->hosts[i])+1);
  }
  
  config__free_unpacked(c, NULL);

  return config;
}

void *pack_config(configuration *config, size_t *out_len) {
  Config c = CONFIG__INIT;
  void *buf;
  size_t len;
  
  c.database_file = config->database_file; //strdup(config->database_file);
  c.hosts = malloc(config->found_ips * sizeof(char *));
  
  int i;
  for (i=0; i<config->found_ips; ++i) {
    c.hosts[i] = config->ips[i];
  }
  c.n_hosts = config->found_ips;

  len = config__get_packed_size(&c);
  buf = malloc(len);
  config__pack(&c, buf);

  if (out_len != NULL) *out_len = len;
  free(c.hosts);
  return buf;
}

configuration *deserialize_config(const char *config, size_t config_len) {
  int cur = 0;
  configuration *c =  malloc(sizeof(configuration)); 
  c->found_ips = 0;

  int i = 0;
  while(cur < config_len && i < MAX_NODES) {
    if (config + cur == '\0') break;
    c->ips[i++] = strndup(config + cur, strlen(config + cur));        
    cur += strlen(config + cur) + 1;
  }
  c->found_ips = i;
  return c;
}

#ifdef __APP__

void prettyprint_config(configuration *config) {
  int i;
  printf("Expected %d IPs\n", config->expected_ips);
  printf("Found %d IPs\n", config->found_ips);
  for (i = 0; i < config->found_ips; ++i) {
    printf("Node %d IP: %s\n", i + 1, config->ips[i]);
  }
}

/* Very basic serialization to pass the IPs from the App the the Enclave
 * could use protobuf if structure becomes more complex
  * Serialized structure: <str>'\0'<str2>'\0'<...>'\0''\0'
  */
char *serialize_config(configuration *config, size_t *len) {
  
  char *buf;
  int i = 0, sofar = 0;

  for (i=0; i<config->found_ips; ++i) {
    sofar += strlen(config->ips[i]) + 1;
  }
  sofar += 1; // For final null terminator

  buf = malloc(sofar);
  *len = sofar;
  sofar = 0;
  for (i=0; i<config->found_ips; ++i) {
    //printf("iter = %d, string len +1 = %d\n", i, strlen(config->ips[i]));
    memcpy(buf + sofar, config->ips[i], strlen(config->ips[i])+1); // Copy null terminator
    sofar += strlen(config->ips[i])+1;
  }
  //printf("sofar = %d\n", sofar);
  
  buf[sofar] = '\0';
  return buf;
}

/* Structure of .ini file:
 *
 * [network]
 * num_nodes=
 * node1=
 * ...
 *
 * [files]
 * database=
 *
 */
static int handler(void *user, const char *section, const char *name,
                   const char *value) {
  char fmt[8];
  configuration *pconfig = (configuration *)user;

  sprintf(fmt, "node%d", pconfig->found_ips + 1);

  #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
  if (MATCH("network", "num_nodes")) {
    pconfig->expected_ips =
        atoi(value); /* This tells us the number of nodes in the system */
    pconfig->found_ips = 0; /* Num ips that we have collected */
    assert(pconfig->expected_ips < MAX_NODES);
    return 1;
  } else if (MATCH("network", fmt)) { /* Match nodeX where X is node number*/
      pconfig->ips[pconfig->found_ips++] = strdup(value);
      return 1;
  } else if (MATCH("files", "database")) {
    pconfig->database_file = strdup(value);
  }
  return 0;
}

configuration *parse_config(const char *path) {

  configuration *config = malloc(sizeof(configuration));
  config->expected_ips = 0; /* set defaults */
  config->found_ips = 0;

  if (ini_parse(path, handler, config) < 0) {
    printf("Can't load '%s'\n", path);
    free(config);
    return NULL;
  }

  return config;
}

void destroy_config(configuration *config) {
  int i;
  free(config->database_file);
  for (i = 0; i < config->found_ips; ++i) {
    free(config->ips[i]);
  }
  free(config);
}

/*
int main(int argc, char *argv[]) {
  assert(argc == 2);

  configuration *config = parse_config(argv[1]);
  if (config != NULL) {
    prettyprint_config(config);
    int i;
    for (i = 0; i < config->found_ips; ++i)
      free(config->ips[i]);
  }
  return 0;
}
*/
#endif /* __APP__ */
