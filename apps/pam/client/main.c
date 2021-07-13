#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <unistd.h>

#include "client_ipc.h"

struct input {
  char cmd[12];
  char username[128];
  char password[128];
};

static void print_input(struct input *input) {
  printf("cmd : %s\n", input->cmd);
 printf("username : %s\n", input->username);
 printf("password : %s\n", input->password);

}

static void usage() { printf("Usage: add/auth <user> <password>\n"); }

/* Implements gen_request_msg() easier to do it here b.c
 * we are using strtok, which mangles the string and
 * is annoying
 */
static void parse_input(char *buf, struct input *input) {

  char *tokens = strtok(buf, " ");
  assert(strlen(tokens) < 12);
  memcpy(input->cmd, tokens, strlen(tokens) + 1);

  tokens = strtok(NULL, " ");
  assert(strlen(tokens) < 128);
  memcpy(input->username, tokens, strlen(tokens) + 1);

  tokens = strtok(NULL, " ");
  assert(strlen(tokens) < 128);
  memcpy(input->password, tokens, strlen(tokens));
  input->password[strlen(tokens)-1] = '\0';
}

int main(int argc, char *argv[]) {
  char buf[500];
  struct input input;
  int ret;

  /*
    if (argc > 1)
      socket_path = argv[1];
  */

  // Read command from stdin
  while ((ret = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
    int response;
    request_type type;


    parse_input(buf, &input);
    print_input(&input);

    if (strcmp(input.cmd, "add") == 0) type = ADD_REQUEST;
    else if (strcmp(input.cmd, "auth") == 0) type = AUTH_REQUEST;
    else {
      usage();
      continue;
    }

    ret = ipc_request(&response, type, input.username, input.password);
    if (ret) {
      printf("ipc_request failed with %d\n", ret);
      exit(ret);
    }

    printf("Service responded with ... %s\n", (response)?"FAIL":"SUCCESS");
    memset(buf, 0, sizeof(buf));
    memset(&input, 0, sizeof(struct input));
  }

}

