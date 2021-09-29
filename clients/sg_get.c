#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "sgd_request.h"


static void usage() {
  fprintf(stderr, "Usage: get <key>\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int ret, status;
  const char *msg;

  if (argc != 2) 
    usage();

  if (strlen(argv[1])+1 > MAX_KEY_LEN) {
    usage();
  }

  ret = sgd_send_request(&status, GET_REQUEST, argv[1], NULL, 0);  
  if (ret) {
    msg = sgd_get_error_msg(ret);
    fprintf(stderr, "%s", msg);
    exit(1);
  }
  
  if (status) {
    fprintf(stderr, "'%s %s' failed to find entry \n", argv[0], argv[1]);
  } else {
    fprintf(stderr, "'%s %s' succeeded\n", argv[0], argv[1]);
  }

  return 0;
}
