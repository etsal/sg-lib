#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "sgx_urts.h"

#include "Enclave_u.h"
#include "sg_interface.h"
#include "sgd_frame.h"
#include "sgd_message.h"

#define DEBUG_PROCESS 1

// char *socket_path = "./socket";
char *socket_path = "/tmp/sg";

extern sgx_enclave_id_t global_eid;

static int process_request(uint8_t *data, size_t data_len) {
  /*
struct request_msg *msg;
  sgx_status_t status;
  int ret;
  //assert(data_len == sizeof(struct request_msg));

  msg = (struct request_msg *)data;
  print_request_msg(msg);

  switch(msg->cmd) {
    case ADD_CMD:
      printf("add ");
      status = ecall_add_user(&ret, msg->key, msg->value);
    break;
    case AUTH_CMD:
      printf("auth ");
      status = ecall_auth_user(&ret, msg->key, msg->value);
    break;
  }

  if (status || ret) {
  // Error
  }

 // printf("%s %s\n", msg->key, msg->value);
 */
}

void *process() {
  struct sockaddr_un addr;
  char buf[100];
  sg_frame_t frame;
  int ret, fd, cl, rc;
  sgx_status_t status;

  sg_frame_ctx_t frame_ctx;
  struct response_msg *response = init_response_msg();

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    return NULL;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  unlink(socket_path);

  // TODO: restrict permissions to socket_path

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("bind error");
    return NULL;
  }

  if (listen(fd, 5) == -1) {
    perror("listen error");
    return NULL;
  }

  init_sg_frame_ctx(&frame_ctx);
  while (1) {
    if ((cl = accept(fd, NULL, NULL)) == -1) {
      perror("accept error");
      continue;
    }
  loop:
    while ((rc = read(cl, &frame, sizeof(sg_frame_t))) > 0) {
      // print_sg_frame(&frame);
      if (process_frame(&frame, &frame_ctx)) {
#ifdef DEBUG_PROCESS
        printf("All frames recieved\n");
#endif
        break;
      }
    }
    if (rc == -1) {
      perror("read");
      free_sg_frame_ctx(&frame_ctx);
      return NULL;
    } else if (rc == 0) {
      printf("EOF\n");
      close(cl);
      return NULL;
    }
    // printf("TODO: process frame_ctx-> data, and write result back to
    // client\n");
#ifdef DEBUG_PROCESS
    printf("request recieved (len %d) : '", frame_ctx.data_len);
    for (int i = 0; i < frame_ctx.data_len; ++i)
      printf("%c", frame_ctx.data[i]);
    printf("'\n");
#endif
    ret = 0;
    // enclave will cast it to struct request_msg
    // ret contains the return value of the sg_XX function, this will be
    // returned to the client
    // status = ecall_process_request(global_eid, &ret, frame_ctx.data,
    // frame_ctx.data_len);

    status = ecall_process_request(global_eid, frame_ctx.data,
                                   frame_ctx.data_len, response);
    if (status) {
      perror("sgx");
      return NULL;
    }

#ifdef DEBUG_PROCESS
    printf("\t+ (%s) After ecall_process_request() response->ret = %d\n",
           __FUNCTION__, response->ret);
#endif
    fflush(stdout);
    fflush(stderr);

    if (write(cl, response, sizeof(struct response_msg)) !=
        sizeof(struct response_msg)) {
      perror("write error");
    }

    clear_sg_frame_ctx(&frame_ctx);
  }
  free(response);
  free_sg_frame_ctx(&frame_ctx);
  return NULL;
}

