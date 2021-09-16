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
#include "sgd_request.h"
#include "nss_sg.h"

/*
 * IMPLEMENTED:
 *   passwd    getpwent(3), getpwent_r(3), getpwnam_r(3), getpwuid_r(3),
 *             setpwent(3), endpwent(3)
 */

/*
 * @param void *rv : holds the value struct passwd **result
 * @param void *mdata: consists of the following
 * 	const char *name
 * 	struct passwd *pwd
 * 	char *buffer
 * 	size_t buffsize
 * 	int* result (should be 'struct passwd **result' but its not)
 *
 */
int nss_sg_getpwnam_r(void *rv, void *mdata, va_list ap) {
  char *name = va_arg(ap, char *);
  struct passwd *pwd = va_arg(ap, struct passwd *);
  char *buffer = va_arg(ap, char *);
  size_t buffsize = va_arg(ap, size_t);
  int *result = va_arg(ap, int *);

  struct passwd **tmp = (struct passwd **) rv;

  printf("+ (nss_sg_getpwnam_r) start\n", __FUNCTION__);

  // Synchronous call to sgd : get_by_user
  int ret = sgd_send_request(result, GET_USER_BY_NAME, name, NULL);
  if (ret) {
    printf("sgd_send_request failed with %d\n", ret);
    *tmp = NULL;
    return NS_UNAVAIL;
  }
  // Fill in struct passwd
  // Set flags accordingly


  return NS_SUCCESS; //NS_UNAVAIL;
}
 /* 
  printf("%s : called\n", __FUNCTION__);
  printf("\t name %s bsize %d\n", name, buffsize);

  int sofar = 0;
  memcpy(buffer, "root", strlen("root")+1);
  sofar += strlen("root")+1;

  memcpy(buffer + sofar, "XXX", strlen("XXX")+1);
  sofar += strlen("XXX")+1;

  printf("buffer : %s\n", buffer);
  printf("buffer + sofar : %s\n", buffer+5);

  pwd->pw_name = buffer;
  pwd->pw_passwd = buffer + 5;
  pwd->pw_class = NULL;
  pwd->pw_gecos = NULL;
  pwd->pw_dir = NULL;
  pwd->pw_shell = NULL;
  pwd->pw_uid = 0;

  *result = NS_SUCCESS; // set to return value
  
  struct passwd **tmp = (struct passwd **)rv;
  *tmp = pwd;

  printf("rv %x pwdptr %x result %x\n", rv, pwd, result);

  return NS_SUCCESS; //NS_UNAVAIL;
}
*/
int nss_sg_getpwuid_r(void *rv, void *mdata, va_list ap) {
  char *name = va_arg(ap, char *);
  struct passwd *pbuf = va_arg(ap, struct passwd *);
  char *buf = va_arg(ap, char *);
  size_t bsize = va_arg(ap, size_t);
  int *res = va_arg(ap, int *);
  char *cp;
  char *nbuf = NULL;
  int rc;
  printf("%s : called\n", __FUNCTION__);
  printf("\t name %s\n", name);
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
 
  return NS_SUCCESS; //NS_UNAVAIL;
}

int nss_sg_endpwent(void *rv, void *mdata, va_list ap) {
  printf("%s : called\n", __FUNCTION__);
 
  return NS_SUCCESS; //NS_UNAVAIL;
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
