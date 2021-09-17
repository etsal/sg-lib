#ifndef __SG_STDFUNC_H__
#define __SG_STDFUNC_H__

#include <stdint.h>
#include <stddef.h>
/*
 * This header defines the C-stdlib functions we needed to manually implement
 * because we need OCALLs in order to preform them
 */

void exit(int status);

void perror(const char *s);

uint32_t htonl(uint32_t hostlong);

char *strcpy(char *dest, const char *src);

void *memmem(const void *haystack, size_t n, const void *needle, size_t m);

int printf(const char *fmt, ...);

int close(int fd);

int atoi(const char *str);

#endif // __SG_STDFUNC_H__
