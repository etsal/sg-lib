#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
//#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
//#include <fcntl.h>
//#include <limits.h>
//#include <sys/stat.h>
//#include <sys/file.h>

//#include "ndb.h"
#include "nss_sg.h"

typedef struct {
  char user[64];
  char password[64];
  uint32_t uid;

} login_t;

#include "sgd_request.h"
#include "sgd_errlist.h"

#define DEBUG 1

static void set_ret_val(int *ret, int action_ret) {

  if (action_ret) {
    *ret = NS_SUCCESS;
  }
  if (action_ret == 321) {  //USER_NOEXIST:
    *ret = NS_NOTFOUND;
  }
  else {
    *ret = NS_TRYAGAIN;
  }
}

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
 
//  int *res = va_arg(ap, int *);
  char *cp;
  char *nbuf = NULL;
  int rc, ret, sg_ret;

#ifdef DEBUG  
  printf("%s : called\n", __FUNCTION__);
#endif

  struct passwd **tmp = (struct passwd **) rv;
  *tmp = NULL;

  struct request_msg *request = gen_request_msg(GET_USER_BY_NAME, name, NULL, 0);
  struct response_msg *response = init_response_msg();

  ret = sgd_sync_make_request(&sg_ret, request, response); 

#ifdef DEBUG
//  printf("%s : action returned %d %d\n", __FUNCTION__, ret, response->ret);
#endif

  if (ret) {
    goto cleanup;
  }
  ret = NS_UNAVAIL;

  if (response->ret == 0 && response->value_len > 0) {
#ifdef DEBUG
//      printf("%s : copying to struct passwd\n", __FUNCTION__);
#endif
      login_to_passwd(pbuf, buf, bsize, (login_t *)response->value);
      *tmp = pbuf;
      ret = NS_SUCCESS;
  } else if (response->ret == 0) {
  	assert(1);
  } else {
	assert(1);		
  }

cleanup:

  free(request);
  free(response);

  return ret;
}

int nss_sg_getpwuid_r(void *rv, void *mdata, va_list ap) {
  int name = va_arg(ap, int);
  struct passwd *pbuf = va_arg(ap, struct passwd *);
  char *buf = va_arg(ap, char *);
  size_t bsize = va_arg(ap, size_t);
  int *res = va_arg(ap, int *);
  char *cp;
  char *nbuf = NULL;
  int rc, ret, sg_ret;

  char id_buf[16];
  snprintf(id_buf, 15, "%d", name);

#ifdef DEBUG  
  printf("%s : called\n", __FUNCTION__);
#endif

  struct request_msg *request = gen_request_msg(GET_USER_BY_ID, id_buf, NULL, 0);
  struct response_msg *response = init_response_msg();

  ret = sgd_sync_make_request(&sg_ret, request, response); 
  if (ret) {
    ret = NS_UNAVAIL;
  } else {
    set_ret_val(&ret, response->ret);
  }

#ifdef DEBUG
  printf("%s : action returned %d\n", __FUNCTION__, ret);
#endif

  free(request);
  free(response);

  return ret;



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
