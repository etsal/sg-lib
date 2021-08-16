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

#define DEBUG_SG 1

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

#ifdef DEBUG_SG
  printf("++ (%s) Calling connect()\n", __FUNCTION__);
#endif

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
  
  assert(strlen(key) + 1 < MAX_KEY_LEN);
  msg->cmd = type;
  memcpy(msg->key, key, strlen(key) + 1);

  if (value != NULL && value_len != 0) {
    assert(msg->value_len < MAX_VALUE_LEN);
    msg->value_len = value_len;
    memcpy(msg->value, value, msg->value_len);
  }
 
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
int sgd_send_request(int *sg_ret, request_type type, const char *key,
                     const char *value) {
  struct ipc_conn conn;
  struct request_msg *request;
  struct response_msg *response = init_response_msg();
  sg_frame_t **frames;
  size_t num_frames;
  int ret;

  assert(type == PUT_REQUEST || type == GET_REQUEST);

#ifdef DEBUG_SG
  printf("+ (%s) start\n", __FUNCTION__);
#endif

  // Make connection to our service
  conn.socket_path = socket_path;
  ret = make_connection(&conn);
  if (ret) {
    return ret;
  }

#ifdef DEBUG_SG
  printf("+ (%s) make_connection() successful\n", __FUNCTION__);
#endif

  // Prepare the request message
  request = prepare_request(type, key, NULL, 0);
  if (request == NULL) {
    close(conn.fd);
    return EX_CANTCREAT;
  }

  // Prepare the frames
  ret = prepare_frames(0, (uint8_t *)request, sizeof(struct request_msg),
                       &frames, &num_frames);
  free(request);
  if (ret) {
    close(conn.fd);
    return EX_CANTCREAT;
  }

#ifdef DEBUG_SG
  printf("+ (%s) prepare_request() successful\n", __FUNCTION__);
#endif

  // Send the frames
  int i;
  for (i = 0; i < num_frames; ++i) {
    if (write(conn.fd, frames[i], sizeof(sg_frame_t)) != sizeof(sg_frame_t)) {
      free_frames(&frames, num_frames);
      close(conn.fd);
      return EX_PROTOCOL;
    }
  }

  free_frames(&frames, num_frames);

#ifdef DEBUG_SG
  printf("+ (%s) write() successful\n", __FUNCTION__);
#endif

  // Read the response & set the return value
  if ((ret = read(conn.fd, response, sizeof(struct response_msg))) > 0) {
    *sg_ret = response->ret;
    ret = 0;
  } else if (ret == -1) {
    ret = errno;
  } else if (ret == 0) { // Recieved EOF
    ret = EX_PROTOCOL;
  } else {
    ret = 1;
  }

#ifdef DEBUG_SG
  printf("+ (%s) closing connection to sgd\n", __FUNCTION__);
  printf("+ (%s) sg_ret = %d ret = %d\n", __FUNCTION__, *sg_ret, ret);
  char buf[MAX_VALUE_LEN+1];
  sprintf(buf, "%s", response->value);
  printf("+ (%s) Recieved %s \n", __FUNCTION__, buf);
#endif

  free(response);
  close(conn.fd);

  return ret;
}


int sgd_send_requestV2(int *sg_ret, struct request_msg *request) {
  struct ipc_conn conn;
  struct response_msg *response = init_response_msg();
  sg_frame_t **frames;
  size_t num_frames;
  int ret;

#ifdef DEBUG_SG
  printf("+ (%s) start\n", __FUNCTION__);
#endif

  // Make connection to our service
  conn.socket_path = socket_path;
  ret = make_connection(&conn);
  if (ret) {
    return ret;
  }

#ifdef DEBUG_SG
  printf("+ (%s) make_connection() successful\n", __FUNCTION__);
#endif


/*
  // Prepare the request message
  request = prepare_request(type, key, NULL, 0);
  if (request == NULL) {
    close(conn.fd);
    return EX_CANTCREAT;
  }
*/

  // Prepare the frames
  ret = prepare_frames(0, (uint8_t *)request, sizeof(struct request_msg),
                       &frames, &num_frames);
  if (ret) {
    close(conn.fd);
    return EX_CANTCREAT;
  }

#ifdef DEBUG_SG
  printf("+ (%s) prepare_request() successful\n", __FUNCTION__);
#endif

  // Send the frames
  int i;
  for (i = 0; i < num_frames; ++i) {
    if (write(conn.fd, frames[i], sizeof(sg_frame_t)) != sizeof(sg_frame_t)) {
      free_frames(&frames, num_frames);
      close(conn.fd);
      return EX_PROTOCOL;
    }
  }

  free_frames(&frames, num_frames);

#ifdef DEBUG_SG
  printf("+ (%s) write() successful\n", __FUNCTION__);
#endif

  // Read the response & set the return value
  if ((ret = read(conn.fd, response, sizeof(struct response_msg))) > 0) {
    *sg_ret = response->ret;
    ret = 0;
  } else if (ret == -1) {
    ret = errno;
  } else if (ret == 0) { // Recieved EOF
    ret = EX_PROTOCOL;
  } else {
    ret = 1;
  }

#ifdef DEBUG_SG
  printf("+ (%s) closing connection to sgd\n", __FUNCTION__);
  printf("+ (%s) sg_ret = %d ret = %d\n", __FUNCTION__, *sg_ret, ret);
  char buf[MAX_VALUE_LEN+1];
  sprintf(buf, "%s", response->value);
  printf("+ (%s) Recieved %s \n", __FUNCTION__, buf);
#endif

  free(response);
  close(conn.fd);

  return ret;
}

