#ifndef __NETWORKING_INTERNAL_H__
#define __NETWORKING_INTERNAL_H__

int host_bind_ocall(const char *host, const char *port);
int host_connect_ocall(const char *host, const char *port);
int accept_client_ocall(int sock_fd);

#endif
