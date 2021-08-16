#ifndef __STDFUNC_H__
#define __STDFUNC_H__

/* This header is useful for enclave functions that use these functions
 * but dont want to include the entire edger generated file.
 */

void ocall_exit(int s);
void ocall_eprintf(const char *str);
void ocall_lprintf(const char *str);
void ocall_sleep(int time);

#endif
