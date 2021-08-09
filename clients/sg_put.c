#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "sgd_request.h"


static void usage() {
  fprintf(stderr, "Usage: put <key> <value>\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int ret, status;
  const char *msg;

  if (argc != 3) 
    usage();

  if (strlen(argv[1])+1 > MAX_KEY_LEN ||
      strlen(argv[2])+1 > MAX_VALUE_LEN) {
    usage();
  }

  ret = sgd_send_request(&status, PUT_REQUEST, argv[1], argv[2]);  
  if (ret) {
    msg = sgd_get_error_msg(ret);
    fprintf(stderr, "%s", msg);
    exit(1);
  }
  return 0;
}
