#ifndef __SG_CONFIG_H__
#define __SG_CONFIG_H__

#define MAX_CONFIG_FILENAME_LEN 1024

typedef struct {
	char statefilename[MAX_CONFIG_FILENAME_LEN + 1];
	char policyfilename[MAX_CONFIG_FILENAME_LEN + 1];

} config_ctx_t;

#endif
