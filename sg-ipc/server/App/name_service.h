#ifndef __NAME_SERVICE_H__
#define __NAME_SERVICE_H__

typedef struct name_service {
  int (* add_user)(struct name_service *ns, const char *username, const char *password);
  int (* auth_user)(struct name_service *ns, const char *username, const char *password);
} name_service_t;

name_service_t *init_name_service();

/*
int add_user(name_service_t *ns, const char *username, const char *password);
int auth_user(name_service_t *ns, const char *username, const char *password);
*/


#endif
