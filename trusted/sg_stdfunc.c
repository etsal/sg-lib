#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sg_stdfunc.h"
#include "sg_t.h" // For boundary calls
#include "sg_common.h"

void
exit(int status)
{
    ocall_exit(status);
}

void
perror(const char *s)
{
	int a;
	return;
}

char *
strcpy(char *dest, const char *src)
{
	size_t i, n;
	n = strlen(src);
	for (i = 0; i <= n && src[i] != '\0'; i++)
		dest[i] = src[i];
	dest[i] = '\0';

	return dest;
}

void *
memmem(const void *haystack, size_t n, const void *needle, size_t m)
{
	if (m > n || !m || !n)
		return NULL;
	if (__builtin_expect((m > 1), 1)) {
		const unsigned char *y = (const unsigned char *)haystack;
		const unsigned char *x = (const unsigned char *)needle;
		size_t j = 0;
		size_t k = 1, l = 2;
		if (x[0] == x[1]) {
			k = 2;
			l = 1;
		}
		while (j <= n - m) {
			if (x[1] != y[j + 1]) {
				j += k;
			} else {
				if (!memcmp(x + 2, y + j + 2, m - 2) &&
				    x[0] == y[j])
					return (void *)&y[j];
				j += l;
			}
		}
	} else {
		/* degenerate case */
		return memchr(haystack, ((unsigned char *)needle)[0], n);
	}
	return NULL;
}

// needed for WolfSSL debugging
int
printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_eprintf(buf);
	return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int
close(int fd)
{
	int ret = 0;
	ocall_close(&ret, fd);
	return ret;
}
