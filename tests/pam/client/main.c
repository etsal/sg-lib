#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc_util.h"
#include "ipc_msg.h"
// char *socket_path = "./socket";
char *socket_path = "/tmp/sg";

static void usage() {
  printf("Usage: add/auth <user> <password>\n");
}

/* Implements gen_ipc_msg() easier to do it here b.c
 * we are using strtok, which mangles the string and
 * is annoying
 */
static uint8_t *prepare_request(char *tokens, size_t *ret) {
  int i;
  struct ipc_msg *msg = malloc(sizeof(struct ipc_msg));

  assert(tokens != NULL);
  memset(msg, 0, sizeof(struct ipc_msg));
  if (strcmp(tokens, "add") == 0) {
    msg->cmd = 0;
  } else if (strcmp(tokens, "auth") == 0) {
    msg->cmd = 1;
  } else {
    usage();
    return NULL;
  }

  i = 0;
  while (tokens && (i < 2)) {
    printf("token: %s\n", tokens);
    tokens = strtok(NULL, " ");
    if (i == 0) {
      assert(strlen(tokens)+1 < MAX_KEY_LEN);
      memcpy(msg->key, tokens, strlen(tokens) + 1);
    } else {
      msg->value_len = strlen(tokens);
      assert(msg->value_len < MAX_VALUE_LEN);
      memcpy(msg->value, tokens, msg->value_len);
    }
    ++i;
  }
  assert(i == 2); // ensures client supplies a command +2 args

  *ret = sizeof(struct ipc_msg);
  return (uint8_t *)msg;
}

int main(int argc, char *argv[]) {
  struct sockaddr_un addr;
  char buf[500];
  int fd, rc;

  if (argc > 1)
    socket_path = argv[1];

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (*socket_path == '\0') {
    *addr.sun_path = '\0';
    strncpy(addr.sun_path + 1, socket_path + 1, sizeof(addr.sun_path) - 2);
  } else {
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("connect error");
    exit(-1);
  }

  // Read command from stdin
  while ((rc = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
    char *tokens;
    uint8_t *request = NULL;
    sg_frame_t **frames;
    size_t request_len = 0, num_frames = 0;

    if (buf[0] == EOF) {
      write(fd, buf, rc);
      exit(1);
    }
    tokens = strtok(buf, " ");

    request = prepare_request(tokens, &request_len);
    if (request == NULL) { // Retry if user submits unknown command
      memset(buf, 0, sizeof(buf));
      continue;
    }
    printf("Request prepared\n");
    prepare_frames(0, request, request_len, &frames, &num_frames);
    for (int i = 0; i < num_frames; ++i) {
      //print_sg_frame(frames[i]);
      //printf("\n");

      if (write(fd, frames[i], sizeof(sg_frame_t)) != sizeof(sg_frame_t)) {
        perror("write error");
        free(request);
        free_frames(&frames, num_frames);
        exit(1);
      }
    }

    memset(buf, 0, sizeof(buf));
    free(request);
    free_frames(&frames, num_frames);
    /*
        if (write(fd, buf, rc) != rc) {
          if (rc > 0)
            fprintf(stderr, "partial write");
          else {
            perror("write error");
            exit(-1);
          }
        }
    */
  }

  return 0;
}
