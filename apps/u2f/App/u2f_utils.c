#include <stdio.h>

#include "u2f_utils.h"

static void
print_bytes(const uint8_t *buf, size_t len)
{
	for (int i = 0; i < len; i++) {
		printf("%02x ", (uint8_t)buf[i]);
		if (/*len > 10 || */ i == len - 1)
			printf("\n");
	}
}

const char *
get_U2FHID_cmd_str(uint8_t cmd)
{
	switch (cmd) {
	case U2FHID_PING:
		// printf("U2FHID_PING");
		return "U2FHID_PING";
	case U2FHID_MSG:
		// printf("U2FHID_MSG");
		return "U2FHID_MSG";
	case U2FHID_LOCK:
		// printf("U2FHID_LOCK");
		return "U2FHID_LOCK";
	case U2FHID_INIT:
		// printf("U2FHID_INIT");
		return "U2FHID_INIT";
	case U2FHID_WINK:
		//("U2FHID_WINK");
		return "U2FHID_WINK";
	default:
		return "UNKNOWN";
	}
}

const char *
get_U2F_cmd_str(uint8_t cmd)
{
	switch (cmd) {
	case U2F_REGISTER:
		return "U2F_REGISTER";
	case U2F_AUTHENTICATE:
		return "U2F_AUTHENTICATE";
	case U2F_VERSION:
		return "U2F_VERSION";
	default:
		return "UNKNOWN";
	}
}

const char *
get_frame_type_str(uint8_t cmd)
{
	switch (cmd) {
	case TYPE_INIT:
		return "TYPE_INIT";
	case TYPE_CONT:
		return "TYPE_CONT";
	default:
		return "UNKNOWN";
	}
}

void
print_frame(U2FHID_FRAME *frame)
{
	printf("\tFrame Type: %s\n", get_frame_type_str(FRAME_TYPE(*frame)));

	if (FRAME_TYPE(*frame) == TYPE_INIT) {
		printf("\tFrame Command: %s\n",
		    get_U2FHID_cmd_str(FRAME_CMD(*frame)));
		printf("\t\tCID \t");
		print_bytes((const uint8_t *)&(frame->cid), 4);
		printf("\t\tCMD \t(0x%x) %s\n", FRAME_CMD(*frame),
		    get_U2FHID_cmd_str(FRAME_CMD(*frame)));
		printf("\t\tBCNTL \t(hi: 0x%x lo: 0x%x) %d\n",
		    frame->init.bcnth, frame->init.bcntl,
		    frame->init.bcnth << 8 | frame->init.bcntl);
		printf("\t\tPAYLOAD  ");
		print_bytes(frame->init.data, HID_RPT_SIZE - 7);
	} else if (FRAME_TYPE(*frame) == TYPE_CONT) {
		printf("\tFrame Sequence Number: %d\n", FRAME_SEQ(*frame));
		printf("\t\tPAYLOAD  ");
		print_bytes(frame->cont.data, HID_RPT_SIZE - 5);

	} else {
		printf("Error, unknown frame type.\n");
	}
}
