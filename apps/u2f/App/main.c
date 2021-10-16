#include <sys/types.h>
#include <dev/usb/usb.h>
#include <dev/usb/usb_ioctl.h>
#include <pthread.h>
#include <cuse.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usbhid.h> 

#include "u2fdev.h"
#include "sgx_eid.h"   	/* sgx_enclave_id_t */
#include "sgx_error.h" 	/* sgx_status_t */
#include "sgx_urts.h"	/* sgx_create_enclave() */

#define DEBUG 1

sgx_enclave_id_t global_eid = 0;

char *hostname_list[] = {"baguette.rcs.uwaterloo.ca", "mantou.rcs.uwaterloo.ca"};

// from: https://github.com/github/SoftU2F/blob/7c3cfc32895ec6afb6f552afcd23e1a735dc8d38/SoftU2FDriver/SoftU2FDevice.hpp
unsigned char const u2fhid_report_descriptor[] = {
	0x06, 0xD0, 0xF1,	//   Usage Page (Reserved 0xF1D0) // bytes are swapped by Firefox to make them litte-endian(why is this a thing they do?)
	0x09, 0x01,			//   Usage (0x01)
	0xA1, 0x01,			//   Collection (Application)
	0x09, 0x20,			//   Usage (0x20)
	0x15, 0x00,			//   Logical Minimum (0)
	0x26, 0xFF, 0x00,	//   Logical Maximum (255)
	0x75, 0x08,			//   Report Size (8)
	0x95, 0x40,			//   Report Count (64)
	0x81, 0x02,			//   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null)
	0x09, 0x21, 		//   Usage (0x21)
	0x15, 0x00, 		//   Logical Minimum (0)
	0x26, 0xFF, 0x00, 	//   Logical Maximum (255)
	0x75, 0x08,	  		//   Report Size (8)
	0x95, 0x40,	  		//   Report Count (64)
	0x91, 0x02, 		//   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,Null Position,Non-volatile)
	0xC0,	    		// End Collection
};

/*
 * Ioctl's have the command encoded in the lower word, and the size of
 * any in or out parameters in the upper word.  The high 3 bits of the
 * upper word are used to encode the in/out status of the parameter.
 *
 *	 31 29 28                     16 15            8 7             0
 *	+---------------------------------------------------------------+
 *	| I/O | Parameter Length        | Command Group | Command       |
 *	+---------------------------------------------------------------+
 */
int
ioctl_(struct cuse_dev *dev, int fflags, unsigned long cmd, void *user_data)
{
#ifdef DEBUG_IOCTL
	//dividerWithText("ioctl");
#endif

	/* Firefox calls ioctl twice with to get USB REPORT */
	if (cmd & IOC_IN) {
#ifdef DEBUG_IOCTL
		printf("%s cmd IOC_IN len %d\n", __FUNCTION__, IOCPARM_LEN(cmd));
#endif
	}
	if (cmd & IOC_OUT) {
#ifdef DEBUG_IOCTL
		printf("%s cmd IOC_OUT %d\n", __FUNCTION__, IOCPARM_LEN(cmd));
#endif
	}

	struct usb_gen_descriptor descp;
	cuse_copy_in(user_data, &descp, sizeof(descp));

#ifdef DEBUG_IOCTL
	/* ugb = usb gen descriptor */
	printf("usb_gen_descriptor.ugd_maxlen %d\n", descp.ugd_maxlen); 
	printf("usb_gen_descriptor.ugd_report_type %d\n", descp.ugd_report_type);
#endif

	cuse_copy_out(&u2fhid_report_descriptor, descp.ugd_data, sizeof(u2fhid_report_descriptor));
	descp.ugd_actlen = sizeof(u2fhid_report_descriptor);
	cuse_copy_out(&descp, user_data, sizeof(descp));

#ifdef DEBUG_IOCTL
	//divider();
#endif

	return 0;
}

int
initialize_enclave(void)
{
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	sgx_status_t status = sgx_create_enclave(
	    "libenclave.signed.so", 1, &token, &updated, &global_eid, NULL);
	return status;
}

int main(void) {

	sgx_status_t status = initialize_enclave();
	if (status != SGX_SUCCESS) {
    fprintf(stderr, "Enclave failed to init %08x\n", status);
		exit(1);
	}
	//printf("+ SGX initialized!\n");

	// Remove this
    int uid = 0;
	char hostname[512];
	char *remote_host;
	gethostname(hostname, 512);
	if (strcmp(hostname, hostname_list[0]) == 0) {
		remote_host = hostname_list[1];
        uid = 0;
	} 
	else {
		remote_host = hostname_list[0];
        uid = 1;
	}
	// Remove this : end
    
    init_u2fdev(uid);

    pthread_t tid;
	int ret = 0;	
	pthread_create(&tid, NULL, listen_updates_u2fdev, (void *)&ret); // Listen for sg updates in background

	ret = cuse_init();
	if (ret) {
		printf("Error, cuse_init failed with %d.\n", ret);
		if (ret == CUSE_ERR_NOT_LOADED) {
			printf("\tRun 'sudo kldload cuse' and re-try!\n");
		}
		exit(1);
	}

	struct cuse_methods cm = { .cm_open = &open_,
		.cm_close = &close_,
		.cm_read = &read_,
		.cm_write = &write_,
		.cm_ioctl = &ioctl_,
		.cm_poll = &poll_ };

	struct cuse_dev *dev = cuse_dev_create(
	    &cm, NULL, NULL, 0, 0, 0777, "uhid_glyptodon");

	printf("+ Cuse device 'uhid_glyptodon' ready!\n");

	ret = 0;
	while (1) {
		ret = cuse_wait_and_process();
		if (ret) {
			printf("Error, cuse_wait_and_process() failed with %d.\n", ret);
			goto exit;
			ret = 1;
		}

		//ecall_send_update(global_eid, &ret, remote_host);
	}

exit:
	pthread_cancel(tid);
	pthread_join(tid, NULL);

	destroy_u2fdev();
	cuse_uninit();
	return ret;
}
