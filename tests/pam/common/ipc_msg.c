#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ipc_msg.h"

struct ipc_msg *gen_ipc_msg(uint8_t cmd, char *key, uint8_t *value,
                            uint32_t value_len) {
  struct ipc_msg *msg;

  assert(strlen(key) < MAX_KEY_LEN);
  assert(value_len < MAX_VALUE_LEN || value_len == MAX_VALUE_LEN);

  msg = malloc(sizeof(struct ipc_msg));
  msg->cmd = cmd;
  msg->value_len = value_len;
  memcpy(msg->key, key, strlen(key) + 1);
  memcpy(msg->value, value, value_len);

  return msg;
}

