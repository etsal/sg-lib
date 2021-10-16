#include <assert.h>
#include <stdio.h> /* vsnprintf */
#include <stdlib.h>
#include <string.h>

#include "stdfunc.h"
#include "Enclave_t.h"

void
exit(int status)
{
    ocall_exit(status);
}

void print_bytes(uint8_t *data, size_t len) {
    for (int i=0; i<len; ++i) {eprintf("%02x", data[i]);}
    eprintf("\n");
}
