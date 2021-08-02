/* Example: parse a simple configuration file */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#ifdef __APP__
#include "inih/ini.h"
#endif

#define DEBUG_SG 1

configuration *deserialize_config(const char *config, size_t config_len) {
  int cur = 0;
  configuration *c =  malloc(sizeof(configuration)); 
  c->found_ips = 0;

  int i = 0;
  while(cur < config_len && i < MAX_NODES) {
    if (config + cur == '\0') break;
    c->ips[i++] = strndup(config + cur, strlen(config + cur));        
    cur += strlen(config + cur) + 1;
#if defined(DEBUG_SG) && defined(__ENCLAVE__)
    eprintf("\t+ (%s) Found: %s\n", __FUNCTION__, c->ips[i-1]);
#endif
  }
  if (!(i < MAX_NODES)) {
#if  defined(DEBUG_SG) && defined(__ENCLAVE__)
    eprintf("\t+ (%s) WARNING: More than %d nodes found in config\n", __FUNCTION__, MAX_NODES);
#endif
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

/* Used to verify that the config file stores everything we expect */
int verify_config(configuration *config) {
  return 1;
}

static int handler(void *user, const char *section, const char *name,
                   const char *value) {
  char fmt[8];
  configuration *pconfig = (configuration *)user;

  #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
  if (MATCH("network", "num_nodes")) {
    pconfig->expected_ips =
        atoi(value); /* This tells us the number of nodes in the system */
    pconfig->found_ips = 0; /* Num ips that we have collected */
    assert(pconfig->expected_ips < MAX_NODES);
    return 1;
  } else {
    sprintf(fmt, "node%d", pconfig->found_ips + 1);
    if (MATCH("network", fmt)) { /* Match nodeX where X is node number*/
      pconfig->ips[pconfig->found_ips++] = strdup(value);

      return 1;
    }
  }
  return 0;
}

configuration *parse_config(const char *path) {

  configuration *config = malloc(sizeof(configuration));
  config->expected_ips = 0; /* set defaults */
  config->found_ips = 0;

  if (ini_parse(path, handler, config) < 0) {
    printf("Can't load 'test.ini'\n");
    free(config);
    return NULL;
  }

  return config;
}

void destroy_config(configuration *config) {
  int i;
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
