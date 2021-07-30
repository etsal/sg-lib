/* Example: parse a simple configuration file */
#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage() {

  printf("Usage: ./app <init file>\n");
}

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

