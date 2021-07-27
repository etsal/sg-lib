#ifndef __NETWORKING_H__
#define __NETWORKING_H__

int host_connect(const char *host, const char *port);
int host_bind(const char *host, const char *port);
int accept_client(int server_fd);

#endif
