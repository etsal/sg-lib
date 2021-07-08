#ifndef __REQUESTS_SG_H__
#define __REQUESTS_SG_H__

#include <stdint.h>

typedef struct sg_request {
  char *key;
  uint32_t value_len;
  void *value;
} sg_request_t;


/* 
 **/
int get(const char *key, void **value, size_t *value_len);

#endif
