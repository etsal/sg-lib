#include <stdint.h>
#include <stdio.h>

#include "db.h"

#define FILENAME "db_test.db"

static char *iota_u64(uint64_t value, char *str, size_t len);
char *names[] = {"alice", "bob", "mallory"};
char *places[] = {"toronto", "montreal", "alberta"};

void test1(void) {
  db_ctx_t db1, db2;
  char *buf;
  size_t len;
  int ret;

  printf("PHASE 0: Initialing new db ...\n");
  ret = init_new_db(&db1, FILENAME);
  if (ret)
    goto fail;

  printf("PHASE 1: Adding keys ...\n");
  for (int i = 0; i < 3; ++i) {
    ret = put_db(&db1, names[i], places[i], strlen(places[i]) + 1);
    if (ret)
      goto fail;
    printf("\tAdded key to db (i=%d)\n", i);
  }

  printf("PHASE 2 : Searching keys ...\n");
  for (int i = 0; i < 3; ++i) {
    ret = get_db(&db1, names[i], (void **)&buf, &len);
    if (!ret)
      goto fail;
    
    //printf("\t '%s' vs. '%s'\n", places[i], buf);
    assert(strcmp(places[i], buf) == 0);
    printf("\tFound key with correct value!\n");
  }

  printf("TEST PASSED!!\n");
  exit(1);

fail:
  printf("TEST FAILED!!\n");
  exit(1);
}

int main(void) {
  test1();
  return 0;
}

static char *iota_u64(uint64_t value, char *str, size_t len) {
  uint64_t tmp = value;
  int count = 0;

  while (1) {
    count++;
    tmp = tmp / 10;
    if (!tmp)
      break;
  }

  if (count > len)
    return NULL;
  str[count] = '\0';

  tmp = value;
  for (int i = 0; i < count; ++i) {
    int leftover = tmp % 10;
    tmp = tmp / 10;
    str[count - (i + 1)] = (char)leftover + 48;
  }
  return str;
}

