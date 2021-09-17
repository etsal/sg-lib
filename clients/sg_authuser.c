#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "sgd_request.h"
#include "util.h"

static void usage() {
  printf("Usage: authuser\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int ret, statusi, sg_ret;
  const char *msg;
  struct request_msg *request;
  struct response_msg *response;

  char username[101];
  char password[101];

  if (argc != 1)
    usage();

  printf("Username: ");
  readUser(username);

  printf("Password: ");
  readPass(password);

  request = gen_request_msg(AUTH_USER, username, password, strlen(password)+1);
  response = init_response_msg();
  ret = sgd_sync_make_request(&sg_ret, request, response);
  if (ret) {
    msg = sgd_get_error_msg(ret);
    printf("%s", msg);
    free(response);
    free(request);
    exit(1);
  }
/*
  if (sg_ret) {
    printf("Failed to find user with %s %s\n", argv[1], argv[2]);
  } else {
    printf("Found user!\n");
  }
*/
  free(response);
  free(request);

  return 0;
}
