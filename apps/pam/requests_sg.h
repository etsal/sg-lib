#ifndef __REQUESTS_SG_H__
#define __REQUESTS_SG_H__

#include <stdint.h>

typedef struct sg_request {
  char *key;
  uint32_t value_len;
  void *value;
  uint32_t ret;
} sg_request_t;


/* 
 **/
int get(sg_request_t *req) {
  req->ret = put_sg(sg_ctx, req->key, &req->value, &req->value_len);
  return req->ret;

}


int put(sg_request_t *req) {
  req->ret = get_sg(sg_ctx, req->key, req->value, req->value_len);
  return req->ret;
}

#endif
