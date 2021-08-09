#ifndef __CLIENT_IPC_H__
#define __CLIENT_IPC_H__

#include "ipc_msg.h"

int ipc_request(int *status, request_type type, const char *username,
                const char *password);

#endif
