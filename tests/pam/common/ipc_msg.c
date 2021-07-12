#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ipc_msg.h"


void print_msg_request(struct msg_request *msg) {
#ifndef __ENCLAVE__
  switch(msg->cmd) {
    case ADD_CMD:
      printf("cmd: ADD\n");
      break;
    case AUTH_CMD:
      printf("cmd: AUTH\n");
      break;
  }
  printf("key: %s\n", msg->key);
  printf("value_len: %d\n", msg->value_len);
  printf("value: ");
  for(int i=0; i<msg->value_len; ++i)
    printf("%c", msg->value[i]);
  printf("\n");
#endif 

}

struct msg_request *gen_msg_request(uint8_t cmd, char *key, uint8_t *value,
                            uint32_t value_len) {
  struct msg_request *msg;

  assert(strlen(key) < MAX_KEY_LEN);
  assert(value_len < MAX_VALUE_LEN || value_len == MAX_VALUE_LEN);

  msg = malloc(sizeof(struct msg_request));
  msg->cmd = cmd;
  msg->value_len = value_len;
  memcpy(msg->key, key, strlen(key) + 1);
  memcpy(msg->value, value, value_len);

  return msg;
}

