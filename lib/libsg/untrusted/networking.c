#include <netinet/in.h>
#include <sys/limits.h>
#include <sys/socket.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h> // snprintf
#include <string.h>
#include <unistd.h>

#include "networking.h"
#include "sg_common.h"

// static pthread_mutex_t lock; //NOT USED

static int select_accept_client(int server_fd);

void ocall_init_networking() {
  // lock = PTHREAD_MUTEX_INITIALIZER;
}

int ocall_host_bind(const char *host, const char *port) {
  return host_bind(host, port);
}

int ocall_host_connect(const char *host, const char *port) {
  return host_connect(host, port);
}

int ocall_accept_client(int sockfd) { return accept_client(sockfd); }

void ocall_gethostname(char *hostname) { gethostname(hostname, 128); }

void ocall_gethostip(char *ip) {
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in *sa;
  char *addr;

  getifaddrs(&ifap);
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
      sa = (struct sockaddr_in *)ifa->ifa_addr;
      addr = inet_ntoa(sa->sin_addr);
      //printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
      if (strcmp("mce0", ifa->ifa_name) == 0) {
        assert(strlen(addr) < INET6_ADDRSTRLEN);
        memcpy(ip, addr, strlen(addr));
        freeifaddrs(ifap);
        return;
      }
    }
  }

  freeifaddrs(ifap);
  assert(1); // Should not reach here

  /*(
    char hostbuf[256];
    int hostname;
    struct hostent *entry;
    char *ip_buf;

    hostname = gethostname(hostbuf, sizeof(hostbuf));
    entry = gethostbyname(hostbuf);

    ip_buf = inet_ntoa(*((struct in_addr*) entry->h_addr_list[0]));
    assert(strlen(ip_buf) < INET6_ADDRSTRLEN);

    memcpy(ip, ip_buf, strlen(ip_buf)+1);
  */
}

/* Defined in fileio.c
int ocall_close(int fd) {
  return close(fd);
}
*/

/* ocall_poll_and_process_updates() To be called in a loop by the enclave
 * @param fds List of sockfds to listen on, needed to typedef it for sgx
 * @param len Length of active_fds
 * @return Populates check_fds that should be read for incoming messages,
 * easier this way, dont need to define an ecall to process each fd individually
 */
int ocall_poll_and_process_updates(int *active_fds, int *check_fds,
                                   size_t len) {
  fd_set read_fd_set;
  int max_fd;
  int ret;

  memset(check_fds, 0, len * sizeof(int));
  FD_ZERO(&read_fd_set);
  max_fd = 0;

  // Set the fds to be watched for reading and max fd
  for (int i = 0; i < len; ++i) {
    if (max_fd < active_fds[i])
      max_fd = active_fds[i];
    if (active_fds[i] > 0)
#ifdef SG_DEBUG
      eprintf("Adding % to read set\n", active_fds[i]);
#endif
    FD_SET(active_fds[i], &read_fd_set);
  }
  max_fd += 1;

#ifdef SG_DEBUG
  eprintf("Before select\n");
#endif
  eprintf("\t+ (%s) Listening for updates from cluster\n", __FUNCTION__);

  ret = select(max_fd, &read_fd_set, NULL, NULL, NULL);
#ifdef SG_DEBUG
  printf("\t+ (%s) Select returned with %d (errno %d)\n", __FUNCTION__, ret,
         errno);
#endif
  if (ret >= 0) {

    // Check for incoming data from desired sockets
    for (int i = 0; i < len; ++i) {
      if (active_fds[i] > 0 && FD_ISSET(active_fds[i], &read_fd_set)) {
        check_fds[i] = 1;
      }
    } // for active_fds
  }   // if (ret >= 0)
  else {
    exit(1);
  }
  return 0;
}

int host_connect(const char *host, const char *port) {
  struct addrinfo hints, *si, *p;
  int fd;
  int err;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  err = getaddrinfo(host, port, &hints, &si);
  if (err != 0) {
#ifdef SG_DEBUG
    eprintf("\t\t + %s: getaddrinfo() %s\n", __FUNCTION__, gai_strerror(err));
#endif
    return -1;
  }
  fd = -1;
  for (p = si; p != NULL; p = p->ai_next) {
    struct sockaddr *sa;
    void *addr;
    char tmp[INET6_ADDRSTRLEN + 50];

    sa = (struct sockaddr *)p->ai_addr;
    if (sa->sa_family == AF_INET) {
      addr = &((struct sockaddr_in *)sa)->sin_addr;
    } else if (sa->sa_family == AF_INET6) {
      addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
    } else {
      addr = NULL;
    }
    if (addr != NULL) {
      inet_ntop(p->ai_family, addr, tmp, sizeof tmp);
    } else {
      // sprintf(tmp, "<unknown family: %d>",
      //(int)sa->sa_family);
    }
    // eprintf("%s : connecting to: %s\n", __FUNCTION__, tmp);
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) {
      // perror("socket()");
#ifdef SG_DEBUG
      eprintf("\t\t + %s: socket() %s\n", __FUNCTION__, strerror(errno));
#endif
      continue;
    }
    if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
      // perror("connect()");
#ifdef SG_DEBUG
      eprintf("\t\t + %s: connect() %s\n", __FUNCTION__, strerror(errno));
#endif
      close(fd);
      continue;
    }
    break;
  }
  if (p == NULL) {
    freeaddrinfo(si);
    return -1;
  }
  freeaddrinfo(si);
  return fd;
}

int host_bind(const char *host, const char *port) {
  struct addrinfo hints, *si, *p;
  int fd;
  int err;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  err = getaddrinfo(host, port, &hints, &si);
  if (err != 0) {
    eprintf("%s: getaddrinfo() %s\n", __FUNCTION__, gai_strerror(err));
    return -1;
  }
  fd = -1;
  for (p = si; p != NULL; p = p->ai_next) {
    struct sockaddr *sa;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    size_t sa_len;
    void *addr;
    char tmp[INET6_ADDRSTRLEN + 50];
    int opt;

    sa = (struct sockaddr *)p->ai_addr;
    if (sa->sa_family == AF_INET) {
      sa4 = *(struct sockaddr_in *)sa;
      sa = (struct sockaddr *)&sa4;
      sa_len = sizeof sa4;
      addr = &sa4.sin_addr;
      if (host == NULL) {
        sa4.sin_addr.s_addr = INADDR_ANY;
      }
    } else if (sa->sa_family == AF_INET6) {
      sa6 = *(struct sockaddr_in6 *)sa;
      sa = (struct sockaddr *)&sa6;
      sa_len = sizeof sa6;
      addr = &sa6.sin6_addr;
      if (host == NULL) {
        sa6.sin6_addr = in6addr_any;
      }
    } else {
      addr = NULL;
      sa_len = p->ai_addrlen;
    }
    if (addr != NULL) {
      inet_ntop(p->ai_family, addr, tmp, sizeof tmp);
    } else {
      sprintf(tmp, "<unknown family: %d>", (int)sa->sa_family);
    }
#ifdef SG_DEBUG
    eprintf("\t+ (%s) binding to: %s\n", __FUNCTION__, tmp);
#endif
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0 || fd == 0) {
      // perror("socket()");
#ifdef SG_DEBUG
      eprintf("\t ++ (%s) socket() %s\n", __FUNCTION__, strerror(errno));
#endif
      continue;
    }
    opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    opt = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt);
    if (bind(fd, sa, sa_len) < 0) {
// perror("bind()");
#ifdef SG_DEBUG
      eprintf("\t ++ (%s) bind() %s\n", __FUNCTION__, strerror(errno));
#endif
      close(fd);
      continue;
    }
    break;
  }
  if (p == NULL) {
#ifdef SG_DEBUG
    eprintf("\t ++ (%s) for loop exhausted %s\n", __FUNCTION__,
            strerror(errno));
#endif
    freeaddrinfo(si);
    return -1;
  }
  freeaddrinfo(si);

  if (listen(fd, 5) < 0) {
    // perror("listen()");
#ifdef SG_DEBUG
    eprintf("\t ++ (%s) listen() %s\n", __FUNCTION__, strerror(errno));
#endif
    close(fd);
    return -1;
  }

#ifdef SG_DEBUG
  eprintf("\t ++ (%s) Exiting with fd = %d\n", __FUNCTION__, fd);
#endif
  return fd;
}

int accept_client(int server_fd) {
  int fd;
  struct sockaddr sa;
  socklen_t sa_len; // client
  char tmp[INET6_ADDRSTRLEN + 50];
  const char *name;

  sa_len = sizeof sa;

#ifdef SG_DEBUG
  eprintf("\t+ %s : Calling accept on server sock %d\n", __FUNCTION__,
          server_fd);
#endif

  fd = accept(server_fd, &sa, &sa_len);
  if (fd < 0) {
    // perror("accept()");
    eprintf("%s : accept() %s\n", __FUNCTION__, strerror(errno));
    return -1;
  }

#ifdef SG_DEBUG
  eprintf("\t+ %s : After calling accept on server sock %d\n", __FUNCTION__,
          server_fd);
#endif

  name = NULL;
  switch (sa.sa_family) {
  case AF_INET:
    name = inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr, tmp,
                     sizeof tmp);
    break;
  case AF_INET6:
    name = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sa)->sin6_addr, tmp,
                     sizeof tmp);
    break;
  }
  if (name == NULL) {
    sprintf(tmp, "<unknown: %lu>", (unsigned long)sa.sa_family);
    name = tmp;
  }
  // eprintf("%s : accepting connection from: %s\n", __FUNCTION__, name);
  return fd;
}

/*
 * Returns -1 on error, 0 when select timesout, >0 on successful accept
 */
int select_accept_client(int server_fd) {
  fd_set read_fd_set;
  int fd, max_fd, ret;
  struct timeval tv = {2, 0};
  struct sockaddr sa;
  socklen_t sa_len; // client
  char tmp[INET6_ADDRSTRLEN + 50];
  const char *name = NULL;

  sa_len = sizeof sa;

  FD_ZERO(&read_fd_set);
  FD_SET(server_fd, &read_fd_set);
  max_fd = server_fd + 1;
#ifdef SG_DEBUG
  printf("\t+ (%s) Calling select() on server_fd %d\n", __FUNCTION__,
         server_fd);
#endif

  ret = select(max_fd, &read_fd_set, NULL, NULL, &tv);
#ifdef SG_DEBUG
  printf("\t+ (%s) Select returned with %d (errno %d)\n", __FUNCTION__, ret,
         errno);
#endif
  if (ret < 0) {
    ret = -1;
    goto cleanup;
  }
  if (ret == 0) {
    ret = 0;
    goto cleanup;
  }
  if (FD_ISSET(server_fd, &read_fd_set)) {
#ifdef SG_DEBUG
    printf("\t+ (%s) Calling accept()\n", __FUNCTION__);
#endif
    fd = accept(server_fd, &sa, &sa_len);
#ifdef SG_DEBUG
    printf("\t+ (%s) accept() returned with %d\n", __FUNCTION__, fd);
#endif
    if (fd < 0) {
      eprintf("%s : accept() %s\n", __FUNCTION__, strerror(errno));
      ret = -1;
      goto cleanup;
    }
    return fd;
  }
cleanup:
  return ret;
}
