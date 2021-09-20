#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "sgd_request.h"
#include "util.h"

static void usage() {
  printf("Usage: putuser \n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int ret, status, sg_ret;
  const char *msg;
  struct request_msg *request;
  struct response_msg *response;
  char username[101];
  char password[101];
  uint32_t nonce = 0;

  if (argc != 1)
    usage();

  printf("Username: ");
  readUser(username);
  printf("Password: ");
  readPass(password);

  request = gen_request_msg(BIND_USER, username, password, strlen(password)+1);
  response = init_response_msg();
  ret = sgd_sync_make_request(&sg_ret, request, response);
  if (ret) {
    msg = sgd_get_error_msg(ret);
    printf("%s", msg);
    free(response);
    free(request);
    exit(1);
  }

  if (response->ret) {
    printf("Error authenticating user %s ... try again.\n", username);
    free(response);
    free(request);
    exit(1);
  } 

  printf("Successfully authenicated user %s ... adding new user.\n", username);
  nonce = response->nonce;
  free(request);
  memset(response, 0, sizeof(struct response_msg));
  memset(username, 0, 101);
  memset(password, 0, 101);

  printf("New Username: ");
  readUser(username);
  printf("New Password: ");
  readPass(password);

  request = gen_request_msg(PUT_USER, username, password, strlen(password)+1);
  request->nonce = nonce;
  ret = sgd_sync_make_request(&sg_ret, request, response);
  if (ret) {
    msg = sgd_get_error_msg(ret);
    printf("%s", msg);
    free(response);
    free(request);
    exit(1);
  }

  free(response);
  free(request);

  return 0;
}
