#ifndef __SG_UTIL_H__
#define __SG_UTIL_H__
#include <stdlib.h>
#include <stdint.h>
int seal(const char *filename, uint8_t *buf, size_t len);
int unseal(const char *filename, uint8_t **buf, size_t *len);

#endif
