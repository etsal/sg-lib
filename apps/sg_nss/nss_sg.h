#ifndef __NSS_TEST_H__
#define __NSS_TEST_H__

//#ifdef __FreeBSD__
#include <nsswitch.h>
//#endif

extern int nss_test_getpwnam_r(void *rv, void *mdata, va_list ap);

extern int nss_test_getpwuid_r(void *rv, void *mdata, va_list ap);

extern int nss_test_getpwent_r(void *rv, void *mdata, va_list ap);

extern int nss_test_setpwent(void *rv, void *mdata, va_list ap);

extern int nss_test_endpwent(void *rv, void *mdata, va_list ap);

//#ifdef __FreeBSD__
extern ns_mtab *nss_module_register(const char *modname, unsigned int *plen,
                                    nss_module_unregister_fn *fptr);
//#endif

#endif /* __NSS_TEST_H__ */
