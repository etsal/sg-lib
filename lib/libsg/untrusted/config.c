/* Example: parse a simple configuration file */

#include "inih/ini.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

void prettyprint_configuration(configuration *config) {
  int i;
  printf("Expected %d IPs\n", config->expected_ips);
  printf("Found %d IPs\n", config->found_ips);
  for (i = 0; i < config->found_ips; ++i) {
    printf("Node %d IP: %s\n", i + 1, config->ips[i]);
  }
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
    //printf("Can't load 'test.ini'\n");
    free(config);
    return NULL;
  }

  return config;
}

/*
int main(int argc, char *argv[]) {
  assert(argc == 2);

  configuration *config = parse_config(argv[1]);
  if (config != NULL) {
    prettyprint_configuration(config);
    int i;
    for (i = 0; i < config->found_ips; ++i)
      free(config->ips[i]);
  }
  return 0;
}
*/
