#include <nss.h>
#include <pwd.h>
#include <stdio.h>
enum nss_status _nss_test_getpwnam_r(const char *name, struct passwd *pwd,
                                     char *buffer, size_t buflen, int *errnop) {
  printf("%s\n", __FUNCTION__);
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_test_getpwuid_r(uid_t uid, struct passwd *pwd,
                                     char *buffer, size_t buflen, int *errnop) {
  printf("%s\n", __FUNCTION__);
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_test_getpwent_r(struct passwd *pwd, char *buffer,
                                     size_t buflen, int *errnop) {
  printf("%s\n", __FUNCTION__);
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_test_setpwent(void) {
  printf("%s\n", __FUNCTION__);
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_test_endpwent(void) {
  printf("%s\n", __FUNCTION__);
  return NSS_STATUS_UNAVAIL;
}

