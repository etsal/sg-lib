#ifndef __SGD_MESSAGE_H__
#define __SGD_MESSAGE_H__

#include <stdint.h>

#warning HARDCODED MAX_KEY_LEN AND MAX_VALUE_LEN, FIX THIS!!!!
#define MAX_KEY_LEN 128
#define MAX_VALUE_LEN 4096
#define MAX_FILEPATH 128

typedef enum {
	PUT_REQUEST, 
	GET_REQUEST, 
	SAVE_REQUEST,
	GET_USER_BY_ID,
	GET_USER_BY_NAME,
  AUTH_USER
} request_type;
/*
typedef struct request_msg {
  uint8_t cmd;
  uint32_t value_len;
  char key[MAX_KEY_LEN];
  uint8_t value[MAX_VALUE_LEN];
} request_msg_t;
*/
typedef struct request_msg {
  uint8_t cmd;
  union {
    char key[MAX_KEY_LEN];
    char filepath[MAX_FILEPATH];
  };
  uint32_t value_len;
  uint8_t value[MAX_VALUE_LEN];
} request_msg_t;

typedef struct response_msg {
  uint8_t ret;
  uint32_t value_len;
  uint32_t value_len_max;
  uint8_t value[MAX_VALUE_LEN];
} response_msg_t;

void print_request_msg(request_msg_t *msg);

struct request_msg *gen_request_msg(uint8_t cmd, char *key, uint8_t *value,
                            uint32_t value_len);

struct response_msg *init_response_msg(); // Allocates memory

void clear_response_msg(struct response_msg *msg);

#endif
