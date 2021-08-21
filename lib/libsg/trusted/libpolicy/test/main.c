#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "re.h"

void test2() {
  int match_len, idx;
  char policies[] = "p:stef/[g-]---\nc:stef/[g-]-[m-]-\n";
  char str[] = "p:stef/g---";
  char str2[] = "p:stef/-p--";
  char *regex, *perms;

  char *policy = strtok(policies, "\n");

  int total = 0;

  while (policy != NULL) {
    ++total;
    regex = policy;

    printf("Attempting to match regex %s against str %s\n", regex, str);
    idx = re_match(regex, str, &match_len);
    printf("%s\n", (idx == -1) ? "FAILED" : "SUCCCEEDED");

    printf("Attempting to match regex %s against str %s\n", regex, str2);
    idx = re_match(regex, str2, &match_len);
    printf("%s\n", (idx == -1) ? "FAILED" : "SUCCCEEDED");

    policy = strtok(NULL, "\n");
  }

  printf("Total policies found = %d\n", total);
}

void test() {

  int match_len, idx;
  char str[] = "p:stef:<h:stef:phonebook.txt>:g---";
  char *regex, *perms;

  idx = re_match("<.*>:....", str, &match_len);

  match_len = 0;

  idx = re_match("<.*>", str, &match_len);
  if (idx) {
    perms = &str[idx + match_len + 1];

    regex = &str[idx + 1];
    str[idx + match_len - 1] = '\0';
  }

  printf("perms %s\nregex %s\n", perms, regex);

  printf("%s : Done\n", __FUNCTION__);
}

int main(int argc, char *argv[]) {
  int ret;

  test2();

  /*

  printf("Running verify_chars() tests ...\n");

  char *key = "/stef";
  ret = verify_chars(key);
  printf("%s to verify '%s'\n", ret == 0 ? "FAILED" : "SUCCEEDED", key);

  key = "stef:stef";
  ret = verify_chars(key);
  printf("%s to verify '%s'\n", ret == 0 ? "FAILED" : "SUCCEEDED", key);

  key = "stef stef";
  ret = verify_chars(key);
  printf("%s to verify '%s'\n", ret == 0 ? "FAILED" : "SUCCEEDED", key);

  printf("Running gen_namespace_key() tests ...\n");
  char *user;
  char *resource;
  type_t t;

  user = "stef";
  key = "4167688805";

  t = DEFAULT_KEY;
  resource = gen_resource_key(user, key, t);
  ret = strcmp(resource == NULL ? "" :  resource, "/home/stef/4167688805");
  printf("%s to generated resource '%s'\n", ret == 0 ? "SUCCEEDED" : "FAILED",
  resource); free(resource);

  t = CREDENTIALS_KEY;
  resource = gen_resource_key(user, NULL, t);
  ret = strcmp(resource == NULL ? "" : resource, "/cred/stef/");
  printf("%s to generated resource '%s'\n", ret == 0 ? "SUCCEEDED" : "FAILED",
  resource); free(resource);


  t = POLICY_KEY;
  resource = gen_resource_key(user, NULL, t);
  ret = strcmp(resource == NULL ? "" : resource , "/policy/stef/");
  printf("%s to generated resource '%s'\n", ret == 0 ? "SUCCEEDED" : "FAILED",
  resource); free(resource);

*/

  return 0;
}
