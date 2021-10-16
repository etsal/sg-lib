#ifndef __STDFUNC_H__
#define __STDFUNC_H__

#include <inttypes.h> 
#include <stdarg.h>


// Declared in common/sg_common.h also
int eprintf(const char *fmt, ...); 
const char *hexstring(const void *vsrc, size_t len);


// U2F project
void print_bytes(uint8_t *data, size_t len);
void exit(int status);

#endif
