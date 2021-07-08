#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc_util.h"

// char *socket_path = "./socket";
char *socket_path = "/tmp/sg";

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

  size_t num_frames = 0;
  sg_frame_t **frames;

  while ((rc = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
    if (buf[0] == EOF) {
      write(fd, buf, rc);
      exit(1);
    } 
    prepare_frames(0, GET_SG, buf, strlen(buf) + 1, &frames, &num_frames);
    for (int i = 0; i < num_frames; ++i) {
      print_sg_frame(frames[i]);
      printf("\n");
      
      if (write(fd, frames[i], sizeof(sg_frame_t)) != sizeof(sg_frame_t)) {
        perror("write error");
        exit(1);
      }
    }

    memset(buf, 0, sizeof(buf));

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
