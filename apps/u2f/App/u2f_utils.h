#ifndef __U2F_UTILS_H__
#define __U2F_UTILS_H__

#include <unistd.h> // uintX_t

#include "u2f.h"
#include "u2f_hid.h"

const char *get_U2FHID_cmd_str(uint8_t cmd);

const char *get_U2F_cmd_str(uint8_t cmd);

const char *get_frame_type_str(uint8_t cmd);

void print_frame(U2FHID_FRAME *frame);

#endif