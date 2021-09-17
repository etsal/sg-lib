#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sgd_message.h"

struct response_msg *init_response_msg() {
  struct response_msg *msg = malloc(sizeof(struct response_msg));
  memset(msg, 0, sizeof(struct response_msg));
  msg->value_len_max = MAX_VALUE_LEN; 
  return msg;
}

void clear_response_msg(struct response_msg *msg) {
  memset(msg, 0, sizeof(struct response_msg));
  msg->value_len_max = MAX_VALUE_LEN; 
}

void print_request_msg(struct request_msg *msg) {
#ifndef __ENCLAVE__
  int i;
  switch(msg->cmd) {
    case PUT_REQUEST:
      printf("cmd: PUT\n");
      break;
    case GET_REQUEST:
      printf("cmd: GET\n");
      break;
  }
  printf("key: %s\n", msg->key);
  printf("value_len: %d\n", msg->value_len);
  printf("value: ");
  for(i=0; i<msg->value_len; ++i)
    printf("%c", msg->value[i]);
  printf("\n");
#endif 

}

struct request_msg *gen_request_msg(uint8_t cmd, char *key, uint8_t *value,
                            uint32_t value_len) {
  struct request_msg *msg;

  assert(strlen(key) < MAX_KEY_LEN);
  assert(value_len < MAX_VALUE_LEN || value_len == MAX_VALUE_LEN);

  msg = malloc(sizeof(struct request_msg));
  msg->cmd = cmd;
  msg->value_len = value_len;
  memcpy(msg->key, key, strlen(key) + 1);
  memcpy(msg->value, value, value_len);

  return msg;
}

