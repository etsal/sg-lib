#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "tiny-regex-c/re.h"
#include "policy.h"

const char *defaults[] = {
  "policy:%s/g---\n",   // User can get their own policy file
  "cred:%s/g-p-\n",     // User can get and modify their own cred file 
  "home:%s:.*/gpmd\n"   // User can get, put, modify, and delete their own home dir file
  "home:.*/g---\n"       // User can get the files of all other user's home dir (and beyond)
};


/* Allocates memory
 * Generates default policy for <user>
 */
char *gen_default_user_policy(const char *user) {

  int user_len = strlen(user);
  int num_defaults = sizeof(defaults) / sizeof(char *);

  char *buf;
  int i, len = 0;

  int *which = malloc(num_defaults * sizeof(int));
  memset(which, 0, num_defaults * sizeof(int));

  // Roughly get an estimate of policy buf size
  for (i=0; i<num_defaults; ++i) {
    int match_len;
    int ret = re_match("%s", defaults[i], &match_len);
    if (ret != -1) {
      len += user_len;
      which[i] = 1;
    }
    len += strlen(defaults[i]);
  }
  len += 1;
  buf = malloc(len * sizeof(char));
  
  // Generate default policies for user
  int sofar = 0;
  for (i=0; i<num_defaults; ++i) {
    if (which[i] == 1) {
      snprintf(buf+sofar, len-sofar, defaults[i], user);
      sofar += strlen(defaults[i]) - 2 + user_len; // Subtract 2 for the %s
    } else {
      snprintf(buf+sofar, len-sofar, defaults[i]);
      sofar += strlen(defaults[i]);
    }
  }
  free(which);
  assert(sofar == len-1);

  buf[sofar] = '\0';

  return buf;
}

