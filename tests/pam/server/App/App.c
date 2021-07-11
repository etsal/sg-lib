#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "sgx_urts.h"

#include "ipc_util.h"
#include "ipc_msg.h"
#include "sg_interface.h"

// char *socket_path = "./socket";
char *socket_path = "/tmp/sg";

sgx_enclave_id_t global_eid = 0;

sgx_status_t initialize_enclave(void) {
  sgx_launch_token_t token = {0};
  int updated = 0;
  sgx_status_t status = sgx_create_enclave("libenclave.signed.so", 1, &token,
                                           &updated, &global_eid, NULL);
  return status;
}

static void process_request(uint8_t *data, size_t data_len) {
  struct ipc_msg *msg;
  //assert(data_len == sizeof(struct ipc_msg));

  msg = (struct ipc_msg *)data;
  print_ipc_msg(msg);
/*
  switch(msg->cmd) {
    case ADD_CMD:
      printf("add ");
    break;
    case AUTH_CMD:
      printf("auth ");
    break;
  }
*/
 // printf("%s %s\n", msg->key, msg->value);
  

}

int process() {
  struct sockaddr_un addr;
  char buf[100];
  sg_frame_t frame;
  int ret, fd, cl, rc;

  sg_frame_ctx_t frame_ctx;

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

  init_sg_frame_ctx(&frame_ctx);
  while (1) {
    if ((cl = accept(fd, NULL, NULL)) == -1) {
      perror("accept error");
      continue;
    }
  loop:
    while ((rc = read(cl, &frame, sizeof(sg_frame_t))) > 0) {
      //print_sg_frame(&frame);
      if (process_frame(&frame, &frame_ctx)) {
        printf("All frames recieved\n");
        break;
      }
    }
    if (rc == -1) {
      perror("read");
      free_sg_frame_ctx(&frame_ctx);
      exit(-1);
    } else if (rc == 0) {
      printf("EOF\n");
      close(cl);
      exit(-1);
    }
    // printf("TODO: process frame_ctx-> data, and write result back to
    // client\n");
    printf("request recieved (len %d) : ", frame_ctx.data_len);
    for(int i=0; i<frame_ctx.data_len; ++i) printf("%c", frame_ctx.data[i]);

    process_request(frame_ctx.data, frame_ctx.data_len);

    clear_sg_frame_ctx(&frame_ctx);
    goto loop;
  }
  free_sg_frame_ctx(&frame_ctx);
  return 0;
}

int main(int argc, char *argv[]) {
  sgx_status_t status;
  int ret;

  status = initialize_enclave();
  if (status) {
    printf("Error %08x @ %d\n", status, __LINE__);
    exit(1);
  }
  printf("Enclave initialized\n");

  ret = initialize_sg();
  if (status) {
    printf("Error %08x @ %d\n", status, __LINE__);
    exit(1);
  }
  printf("SG initialized\nRunning service ...\n");

  ret = process();

  return ret;
}
