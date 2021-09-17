#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
//#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
//#include <fcntl.h>
//#include <limits.h>
//#include <sys/stat.h>
//#include <sys/file.h>

//#include "ndb.h"
#include "nss_sg.h"

/*
 * IMPLEMENTED:
 *   passwd    getpwent(3), getpwent_r(3), getpwnam_r(3), getpwuid_r(3),
 *             setpwent(3), endpwent(3)
 */

int nss_sg_getpwnam_r(void *rv, void *mdata, va_list ap) {
  char *name = va_arg(ap, char *);
  struct passwd *pbuf = va_arg(ap, struct passwd *);
  char *buf = va_arg(ap, char *);
  size_t bsize = va_arg(ap, size_t);
  int *res = va_arg(ap, int *);
  char *cp;
  char *nbuf = NULL;
  int rc;
  printf("%s : called\n", __FUNCTION__);
  return NS_UNAVAIL;
}

int nss_sg_getpwuid_r(void *rv, void *mdata, va_list ap) {
  int name = va_arg(ap, int);
  struct passwd *pbuf = va_arg(ap, struct passwd *);
  char *buf = va_arg(ap, char *);
  size_t bsize = va_arg(ap, size_t);
  int *res = va_arg(ap, int *);
  char *cp;
  char *nbuf = NULL;
  int rc;
  printf("%s : called\n", __FUNCTION__);
  return NS_UNAVAIL;
}

int nss_sg_getpwent_r(void *rv, void *mdata, va_list ap) {
  struct passwd *pbuf = va_arg(ap, struct passwd *);
  char *buf = va_arg(ap, char *);
  size_t bsize = va_arg(ap, size_t);
  int *res = va_arg(ap, int *);
  printf("%s : called\n", __FUNCTION__);
  return NS_UNAVAIL;
}

int nss_sg_setpwent(void *rv, void *mdata, va_list ap) {
  int stayopen = va_arg(ap, int);
  printf("%s : called\n", __FUNCTION__);
  return NS_UNAVAIL;
}

int nss_sg_endpwent(void *rv, void *mdata, va_list ap) {
  printf("%s : called\n", __FUNCTION__);
  return NS_UNAVAIL;
}

//#ifdef __FreeBSD__
ns_mtab *nss_module_register(const char *source, unsigned int *mtabsize,
                             nss_module_unregister_fn *unreg) {

  static ns_mtab methods[] = {
      {"passwd", "getpwnam_r", &nss_sg_getpwnam_r, 0},
      {"passwd", "getpwuid_r", &nss_sg_getpwuid_r, 0},
      {"passwd", "getpwent_r", &nss_sg_getpwent_r, 0},
      {"passwd", "setpwent", &nss_sg_setpwent, 0},
      {"passwd", "endpwent", &nss_sg_endpwent, 0}};

  *mtabsize = sizeof(methods) / sizeof(methods[0]);
  *unreg = NULL;
  return (methods);
}
//#endif __FreeBSD
