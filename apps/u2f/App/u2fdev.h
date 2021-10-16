#ifndef __U2FDEV_H__
#define __U2FDEV_H__

#include <cuse.h>
#define U2F_PROTOCOL_VERSION 2

void init_u2fdev(int uid);
void destroy_u2fdev();

int open_(struct cuse_dev *dev, int fflags);
int close_(struct cuse_dev *dev, int fflags);
int poll_(struct cuse_dev *dev, int fflags, int events);
int read_(struct cuse_dev *dev, int fflags, void *user_ptr, int len);
int write_(struct cuse_dev *dev, int fflags, const void *user_ptr, int len);
void* listen_updates_u2fdev();

#endif
