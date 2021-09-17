#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "sgd_request.h"

static void usage() {
  printf("Usage: getuserby [id/name] <key>\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int ret, statusi, sg_ret;
  const char *msg;
  struct request_msg *request;
  struct response_msg *response;

  if (argc != 3)
    usage();

  if (strlen(argv[2]) + 1 > MAX_KEY_LEN)
    usage();

  if (strcmp(argv[1], "id") == 0) {
    request = gen_request_msg(GET_USER_BY_ID, argv[2], NULL, 0);
  } else if (strcmp(argv[1], "name") == 0) {
    request = gen_request_msg(GET_USER_BY_NAME, argv[2], NULL, 0);
  } else {
    usage();
  }

  response = init_response_msg();
  ret = sgd_sync_make_request(&sg_ret, request, response);
  if (ret) {
    msg = sgd_get_error_msg(ret);
    printf("%s", msg);
    free(response);
    free(request);
    exit(1);
  }

  if (sg_ret) {
    printf("Failed to find user with %s %s\n", argv[1], argv[2]);
  } else {
    printf("Found user!\n");
  }

  free(response);
  free(request);

  return 0;
}
