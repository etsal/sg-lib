#ifndef __SGD_REQUEST_H__
#define __SGD_REQUEST_H__

#include "sgd_message.h"

int sgd_send_request(int *sg_ret, request_type type, const char *key, const char *value, size_t value_len);

int sgd_send_requestV2(int *sg_ret, struct request_msg *request);
const char *sgd_get_error_msg(int ret);

int sgd_sync_make_request(int *sg_ret, struct request_msg *request,
                     struct response_msg *response);

#endif
