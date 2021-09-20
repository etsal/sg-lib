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

#include "../../lib/libsg/include/policy_defs.h"

/*
 * IMPLEMENTED:
 *   passwd    getpwent(3), getpwent_r(3), getpwnam_r(3), getpwuid_r(3),
 *             setpwent(3), endpwent(3)
 *
 * Note: I believe that the re-entrant functions are correctly implemented because
 * the sgd serializes the requests, so we can place calls in some serial order
 */

static int login_to_passwd(struct passwd *pwd, char *buf, size_t len, login_t *login) {
  int sofar = 0;

  sofar += strlen(login->user)+1;
  if (sofar > len) {
    return 1;
  }
  memcpy(buf, login->user, strlen(login->user)+1);
  pwd->pw_name = buf;

  sofar += strlen(login->password)+1;
  if (sofar > len) {
    return 1;
  }
  memcpy(buf + sofar, login->password, strlen(login->password)+1);
  pwd->pw_passwd = buf + sofar;

  pwd->pw_uid = login->uid;
  pwd->pw_gid = 0;
  pwd->pw_change = 0;
  pwd->pw_class = NULL;
  pwd->pw_gecos = NULL;
  pwd->pw_dir = NULL;
  pwd->pw_shell = NULL;
  pwd->pw_expire = 0;
  pwd->pw_fields = 0;

  return 0;
}

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

  int sg_ret;

  struct passwd **tmp = (struct passwd **) rv;
  *tmp = NULL;

  struct request_msg *request = gen_request_msg(GET_USER_BY_NAME, name, NULL, 0);
  struct response_msg *response = init_response_msg();

  // Synchronous call to sgd : get_by_user
  int ret = sgd_sync_make_request(&sg_ret, request, response);
  if (ret) {
    printf("sgd_send_request failed with %d\n", ret);
    free(response);
    free(request);
    return NS_UNAVAIL;
  }

  // TODO check sg_ret

  login_to_passwd(pwd, buffer, buffsize, (login_t *)response->value);
  *tmp = pwd;

  free(response);
  free(request);

  printf("+ (%s) complete\n", __FUNCTION__);
  return NS_SUCCESS; //NS_UNAVAIL;
}

int nss_sg_getpwuid_r(void *rv, void *mdata, va_list ap) {
  int uid = va_arg(ap, int);
  struct passwd *pwd = va_arg(ap, struct passwd *);
  char *buf = va_arg(ap, char *);
  size_t bsize = va_arg(ap, size_t);
  int *res = va_arg(ap, int *);
  
  int sg_ret;

  struct passwd **tmp = (struct passwd **) rv;
  *tmp = NULL;

  char uid_str[12];
  snprintf(uid_str, 11, "%d", uid);
	
  struct request_msg *request = gen_request_msg(GET_USER_BY_ID, uid_str, NULL, 0);
  struct response_msg *response = init_response_msg();

  // Synchronous call to sgd : get_by_user
  int ret = sgd_sync_make_request(&sg_ret, request, response);
  if (ret) {
    printf("sgd_send_request failed with %d\n", ret);
    free(response);
    free(request);
    return NS_UNAVAIL;
  }

  login_to_passwd(pwd, buf, bsize, (login_t *)response->value);
  *tmp = pwd;

  free(response);
  free(request);

  printf("+ (%s) complete\n", __FUNCTION__);
  return NS_SUCCESS; //NS_UNAVAIL;
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
