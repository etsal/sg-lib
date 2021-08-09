#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <unistd.h>

#include "sgd_frame.h"
#include "sgd_request.h"

char *socket_path = "/tmp/sg";

struct ipc_conn {
  char *socket_path;
  int fd;
};

static int make_connection(struct ipc_conn *conn);
static struct request_msg *prepare_request(request_type type, const char *key,
                                           const void *value, size_t value_len);

static int make_connection(struct ipc_conn *conn) {
  struct sockaddr_un addr;

  if ((conn->fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    return EX_PROTOCOL;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (*(conn->socket_path) == '\0') {
    *addr.sun_path = '\0';
    strncpy(addr.sun_path + 1, conn->socket_path + 1,
            sizeof(addr.sun_path) - 2);
  } else {
    strncpy(addr.sun_path, conn->socket_path, sizeof(addr.sun_path) - 1);
  }

printf("before connect\n");

  if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    //return EX_PROTOCOL;
    return errno;
  }

  return 0;
}

static struct request_msg *prepare_request(request_type type, const char *key,
                                           const void *value,
                                           size_t value_len) {
  struct request_msg *msg;

  assert(type == PUT_REQUEST || type == GET_REQUEST);
  msg = malloc(sizeof(struct request_msg));
  memset(msg, 0, sizeof(struct request_msg));

  msg->cmd = type;

  assert(strlen(value) + 1 < MAX_KEY_LEN);
  memcpy(msg->key, key, strlen(key) + 1);

  msg->value_len = value_len;
  assert(msg->value_len < MAX_VALUE_LEN);
  memcpy(msg->value, value, msg->value_len);

  //  print_request_msg(msg);

  return msg;
}

const char *sgd_send_err_msgs[] = {"Error, failed when talking to sg daemon.\n",
                "Error, failed to create message.\n"};

const char *sgd_get_error_msg(int ret) {
  if (ret == EX_PROTOCOL) return sgd_send_err_msgs[0];
  if (ret == EX_CANTCREAT) return sgd_send_err_msgs[1];
  return strerror(ret); // Otherwise it's errno
}

/* 0 on success, >0 on error , status holds the request return code*/
int sgd_send_request(int *status, request_type type, const char *key,
                     const char *value) {
  struct ipc_conn conn;
  struct request_msg *req_msg;
  struct response_msg resp_msg;
  sg_frame_t **frames;
  size_t num_frames;
  int ret;

  assert(type == PUT_REQUEST || type == GET_REQUEST);

  printf("%s start\n", __FUNCTION__);

  // Make connection to our service
  conn.socket_path = socket_path;
  ret = make_connection(&conn);
  if (ret) {
    return ret;
  }

  printf("make_connection() successful\n");

  // Prepare the request message
  req_msg = prepare_request(type, key, value, strlen(value) + 1);
  if (req_msg == NULL) {
    close(conn.fd);
    return EX_CANTCREAT;
  }

  // Prepare the frames
  ret = prepare_frames(0, (uint8_t *)req_msg, sizeof(struct request_msg),
                       &frames, &num_frames);
  if (ret) {
    free(req_msg);
    close(conn.fd);
    return EX_CANTCREAT;
  }


  printf("prepare_request() successful\n");


  // Send the frames
  int i;
  for (i = 0; i < num_frames; ++i) {
    if (write(conn.fd, frames[i], sizeof(sg_frame_t)) != sizeof(sg_frame_t)) {
      free(req_msg);
      free_frames(&frames, num_frames);
      close(conn.fd);
      return EX_PROTOCOL;
    }
  }

  free(req_msg);
  free_frames(&frames, num_frames);

  printf("write() successful\n");

  // Read the response & set the return value
  memset(&resp_msg, 0, sizeof(struct response_msg));
  if ((ret = read(conn.fd, &resp_msg, sizeof(struct response_msg))) > 0) {
    *status = resp_msg.ret;
    ret = 0;
  } else if (ret == -1) {
    ret = errno;
  } else if (ret == 0) { // Recieved EOF
    ret = EX_PROTOCOL;
  } else {
    ret = 1;
  }

  printf("end\n");

  close(conn.fd);

  return ret;
}

