#ifndef __SG_LOG_H__
#define __SG_LOG_H__



/* Truncates file at filepath */
void init_log(const char *filepath);

/* Appends file at filepath */
int write_blob_log(const char *buf);

#endif
