#include "sgx_urts.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "Enclave_u.h"
#include "sg_interface.h"
#include "sgd_frame.h"
#include "sgd_message.h"

#define DEBUG_IPC_UTIL 1

char *socket_path = "/tmp/sg";

extern sgx_enclave_id_t global_eid;

/* Returns a sockfd for the UNIX domain socket
 * returns -1 on error, >= 0 on success
 */
int prepare_ipc_socket() {
  struct sockaddr_un addr;
  int ret, fd;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  unlink(socket_path);

  // TODO: restrict permissions to socket_path??

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("bind error");
    close(fd);
    return -1;
  }

  if (listen(fd, 5) == -1) {
    perror("listen error");
    close(fd);
    return -1;
  }

  return fd;
}

int process_ipc_message(int fd) {
  char buf[100];
  sg_frame_t frame;
  int ret, cl, rc;
  sgx_status_t status;
  sg_frame_ctx_t frame_ctx;
  struct response_msg *response;

  response = init_response_msg();
  init_sg_frame_ctx(&frame_ctx);

  if ((cl = accept(fd, NULL, NULL)) == -1) {
    // perror("accept error");
    ret = errno;
    goto cleanup;
  }

  while ((rc = read(cl, &frame, sizeof(sg_frame_t))) > 0) {
#ifdef DEBUG_IPC_UTIL
    // print_sg_frame(&frame);
#endif
    if (process_frame(&frame, &frame_ctx)) {
#ifdef DEBUG_IPC_UTIL
      printf("+ (%s) All frames recieved\n", __FUNCTION__);
#endif
      break;
    }
  }

  if (rc == -1) {
    ret = 1;
    goto cleanup;
  }
  if (rc == 0) {
    close(cl);
    ret = 1;
    goto cleanup;
  }

#ifdef DEBUG_IPC_UTIL
  printf("+ (%s) request recieved (len %d) : '", __FUNCTION__,
         frame_ctx.data_len);
  for (int i = 0; i < frame_ctx.data_len; ++i)
    printf("%c", frame_ctx.data[i]);
  printf("'\n");

  print_request_msg((struct request_msg *)frame_ctx.data);
#endif

  // enclave will cast it to struct request_msg
  // ret contains the return value of the sg_XX function, this will be
  // returned to the client

  ret = 0;
  status = ecall_process_request(global_eid, frame_ctx.data, frame_ctx.data_len,
                                 response);
  if (status != SGX_SUCCESS) {
    perror("sgx");
    ret = 1;
    goto cleanup;
  }

#ifdef DEBUG_IPC_UTIL
  printf("\t+ (%s) After ecall_process_request() response->ret = %d\n",
         __FUNCTION__, response->ret);
#endif

  if (write(cl, response, sizeof(struct response_msg)) !=
      sizeof(struct response_msg)) {
    perror("write error");
    ret = 1;
  }

cleanup:
  free(response);
  free_sg_frame_ctx(&frame_ctx);
  close(cl);
  return ret;
}

