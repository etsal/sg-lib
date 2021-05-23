#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h> // snprintf
#include <string.h>
#include <unistd.h>

#include "sg_common.h"
#include "networking.h"

int
ocall_host_bind(const char *host, const char *port)
{
	return host_bind(host, port);
}

int
ocall_host_connect(const char *host, const char *port)
{
	return host_connect(host, port);
}

int
ocall_accept_client(int sockfd)
{
	return accept_client(sockfd);
}

/* Defined in fileio.c
int ocall_close(int fd) {
  return close(fd);
}
*/

int
host_connect(const char *host, const char *port)
{
	struct addrinfo hints, *si, *p;
	int fd;
	int err;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hints, &si);
	if (err != 0) {
		eprintf(
		    "%s : getaddrinfo() %s\n", __FUNCTION__, gai_strerror(err));
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
		//eprintf("%s : connecting to: %s\n", __FUNCTION__, tmp);
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) {
			// perror("socket()");
			eprintf(
			    "%s: socket() %s\n", __FUNCTION__, strerror(errno));
			continue;
		}
		if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
			// perror("connect()");
			eprintf("%s: connect() %s\n", __FUNCTION__,
			    strerror(errno));
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

int
host_bind(const char *host, const char *port)
{
	struct addrinfo hints, *si, *p;
	int fd;
	int err;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hints, &si);
	if (err != 0) {
		eprintf(
		    "%s: getaddrinfo() %s\n", __FUNCTION__, gai_strerror(err));
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
			sprintf(
			    tmp, "<unknown family: %d>", (int)sa->sa_family);
		}
		//eprintf("\t+ %s : binding to: %s\n", __FUNCTION__, tmp);
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0 || fd == 0) {
			// perror("socket()");
			eprintf(
			    "%s: socket() %s\n", __FUNCTION__, strerror(errno));
			continue;
		}
		opt = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
		opt = 0;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt);
		if (bind(fd, sa, sa_len) < 0) {
			// perror("bind()");
			eprintf(
			    "%s: bind() %s\n", __FUNCTION__, strerror(errno));
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

	if (listen(fd, 5) < 0) {
		// perror("listen()");
		eprintf("%s: listen() %s\n", __FUNCTION__, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int
accept_client(int server_fd)
{
	int fd;
	struct sockaddr sa;
	socklen_t sa_len;
	char tmp[INET6_ADDRSTRLEN + 50];
	const char *name;

	sa_len = sizeof sa;
    
    //eprintf("\t+ %s : Calling accept on server sock %d\n", __FUNCTION__, server_fd);

	fd = accept(server_fd, &sa, &sa_len);
	if (fd < 0) {
		// perror("accept()");
		eprintf("%s : accept() %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}
	name = NULL;
	switch (sa.sa_family) {
	case AF_INET:
		name = inet_ntop(AF_INET,
		    &((struct sockaddr_in *)&sa)->sin_addr, tmp, sizeof tmp);
		break;
	case AF_INET6:
		name = inet_ntop(AF_INET6,
		    &((struct sockaddr_in6 *)&sa)->sin6_addr, tmp, sizeof tmp);
		break;
	}
	if (name == NULL) {
		sprintf(tmp, "<unknown: %lu>", (unsigned long)sa.sa_family);
		name = tmp;
	}
	//eprintf("%s : accepting connection from: %s\n", __FUNCTION__, name);
	return fd;
}
