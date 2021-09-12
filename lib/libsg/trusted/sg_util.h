#ifndef __SG_UTIL_H__
#define __SG_UTIL_H__
#include <stdlib.h>
#include <stdint.h>

char *iota_u64(uint64_t value, char *str, size_t len); 
void gen_log_msg(int cmd, const char *key, int sg_ret);

int seal(const char *filename, uint8_t *buf, size_t len);
int unseal(const char *filename, uint8_t **buf, size_t *len);

#endif
