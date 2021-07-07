#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>

#include "ipc_util.h"

// char *socket_path = "./socket";
char *socket_path = "/tmp/sg";


/* This is the sg daemon interact that will listen for UNIX domain socket connections
and make the correct corresponding enclave call to handle the request using sg
*/

int process() {
  struct sockaddr_un addr;
  //char buf[100];
  sg_frame_t frame;
  int fd, cl, rc;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  unlink(socket_path);

  // TODO: restrict permissions to socket_path

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("bind error");
    exit(-1);
  }

  if (listen(fd, 5) == -1) {
    perror("listen error");
    exit(-1);
  }

  while (1) {
    if ((cl = accept(fd, NULL, NULL)) == -1) {
      perror("accept error");
      continue;
    }

    while ((rc = read(cl, &frame, sizeof(sg_frame_t))) > 0) {
      //printf("read %u bytes: %.*s\n", rc, rc, buf);
      process_frame(&frame);
    }
    if (rc == -1) {
      perror("read");
      exit(-1);
    } else if (rc == 0) {
      printf("EOF\n");
      close(cl);
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {

  int ret = process();

  return ret;

}
