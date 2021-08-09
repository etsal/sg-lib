#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <unistd.h>

#include "ipc_msg.h"
#include "ipc_util.h"
// char *socket_path = "./socket";
char *socket_path = "/tmp/sg";

struct ipc_conn {
  char *socket_path;
  int fd;
};

static int make_connection(struct ipc_conn *conn);
static struct request_msg *prepare_request(request_type type, const char *username, const char *password);

static int
make_connection(struct ipc_conn *conn) {
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

  if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    return EX_PROTOCOL;
  }

  return 0;
}

static struct request_msg *
prepare_request(request_type type, const char *username, const char *password) {
  struct request_msg *msg;

  assert(type == ADD_REQUEST || type == AUTH_REQUEST);
  msg = malloc(sizeof(struct request_msg));
  memset(msg, 0, sizeof(struct request_msg));

  msg->cmd = type;

  assert(strlen(username) + 1 < MAX_KEY_LEN);
  memcpy(msg->key, username, strlen(username) + 1);

  msg->value_len = strlen(password);
  assert(msg->value_len < MAX_VALUE_LEN);
  memcpy(msg->value, password, msg->value_len);

  print_request_msg(msg);

  return msg;
}

/* 0 on success, >0 on error , status holds the request return code*/
int ipc_request(int *status, request_type type, const char *username, const char *password) {
  struct ipc_conn conn;
  struct request_msg *req_msg;
  struct response_msg resp_msg;
  sg_frame_t **frames;
  size_t num_frames;
  int ret;

  assert(type == ADD_REQUEST || type == AUTH_REQUEST);

  // Make connection to our service
  conn.socket_path = socket_path;
  ret = make_connection(&conn);
  if (ret) {
    return ret;
  }

  // Prepare the request message
  req_msg = prepare_request(type, username, password);
  if (req_msg == NULL) {
    close(conn.fd);
    return EX_CANTCREAT;
  }

  // Prepare the frames
  ret = prepare_frames(0, (uint8_t *)req_msg, sizeof(struct request_msg), &frames,
                       &num_frames);
  if (ret) {
    free(req_msg);
    close(conn.fd);
    return EX_CANTCREAT;
  }

  // Send the frames
  for (int i=0; i<num_frames; ++i) {
    if (write(conn.fd, frames[i], sizeof(sg_frame_t)) != sizeof(sg_frame_t)) {
     free(req_msg);
     free_frames(&frames, num_frames);
     close(conn.fd);
     return EX_PROTOCOL;
   }
  }

  free(req_msg);
  free_frames(&frames, num_frames);

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

  close(conn.fd);

  return ret;
}

