#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "sgd_request.h"


static void usage() {
  fprintf(stderr, "Usage: save <filepath>\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int ret, status;
  const char *msg;

  struct request_msg request;

  if (argc != 2) 
    usage();

  if (strlen(argv[1])+1 > MAX_KEY_LEN) {
    usage();
  }

  memset(&request, 0, sizeof(struct request_msg));
  request.cmd = SAVE_REQUEST;
  memcpy(request.filepath, argv[1], strlen(argv[1])+1);
  request.value_len=0;

  ret = sgd_send_requestV2(&status, &request);  
  if (ret) {
    msg = sgd_get_error_msg(ret);
    fprintf(stderr, "%s", msg);
    exit(1);
  }
  
  if (status) {
    fprintf(stderr, "'%s %s' failed to save\n", argv[0], argv[1]);
  } else {
    fprintf(stderr, "'%s %s' successfully saved\n", argv[0], argv[1]);
  }

  return 0;
}
