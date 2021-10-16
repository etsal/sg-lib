#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
ocall_printf(const char *str)
{
    fprintf(stdout, str, strlen(str));
    return;
}
/*
void
ocall_exit(int s)
{
    exit(s);
}
*/
