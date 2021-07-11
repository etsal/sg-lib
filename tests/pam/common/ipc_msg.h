#ifndef __IPC_MSG_H__
#define __IPC_MSG_H__
#include <stdint.h>

#warning HARDCODED MAX_KEY_LEN AND MAX_VALUE_LEN, FIX THIS!!!!
#define MAX_KEY_LEN 128
#define MAX_VALUE_LEN 4096

typedef enum {ADD_CMD, AUTH_CMD} cmd_type;

typedef struct ipc_msg {
  uint8_t cmd;
  uint32_t value_len;
  char key[MAX_KEY_LEN];
  uint8_t value[MAX_VALUE_LEN];
} ipc_msg_t;

void print_ipc_msg(struct ipc_msg *msg);

struct ipc_msg *gen_ipc_msg(uint8_t cmd, char *key, uint8_t *value,
                            uint32_t value_len);

#endif
