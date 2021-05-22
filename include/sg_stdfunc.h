#ifndef __STD_FUNCTIONS_H__
#define __STD_FUNCTIONS_H__

#include <stdlib.h>

void exit(int s);

void perror(const char *s);

char *strcpy(char *dest, const char *src);

void *memmem(const void *haystack, size_t n, const void *needle, size_t m);

int printf(const char *fmt, ...);

int close(int fd);

#endif
