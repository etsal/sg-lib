#include <stdint.h>
#include <stdio.h>

#include "db.h"

#define FILENAME "db_test.db"

static char *iota_u64(uint64_t value, char *str, size_t len);
char *names[] = {"alice", "bob", "mallory"};
char *places[] = {"toronto", "montreal", "alberta"};

int test1(void) {
  db_ctx_t db1, db2;
  char *buf;
  size_t len;
  int ret;

  printf("Checking get() & put() methods ...\n");
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

    // printf("\t '%s' vs. '%s'\n", places[i], buf);
    assert(strcmp(places[i], buf) == 0);
    printf("\tFound key with correct value!\n");
  }

  printf("TEST PASSED!!\n");
  return 0;

fail:
  printf("TEST FAILED!!\n");
  return 1;
}

int test2(void) {
  int test_num = 0;
  db_ctx_t db1, db2;
  uint8_t *buf;
  size_t len;
  int ret;
  
  printf("Checking de/serialization methods ...\n");
  printf("PHASE 1: Initializing new dbs ...\n");

  ret = init_new_db(&db1, FILENAME);
  ret += init_new_db(&db2, FILENAME);
  if (ret)
    goto fail;

  printf("PHASE 2: Adding keys ...\n");
  ret = put_db(&db1, "1", "one", strlen("one"));
  ret += put_db(&db1, "2", "two", strlen("two"));
  ret += put_db(&db1, "3", "three", strlen("three"));
  ret += put_db(&db1, "4", "four", strlen("four"));

  printf("PHASE 3: Serializing db ...\n");
  serialize_db(&db1, &buf, &len);

  printf("PHASE 4: Deserializing db ...\n"); 
  deserialize_db(&db2, buf, len);

  if (!compare_db(&db1, &db2)) {
    printf("TEST (%d/2) PASSED!!\n", ++test_num);
  }

  ret = put_db(&db2, "5", "five", strlen("five"));
  if (compare_db(&db1, &db2)) {
    printf("TEST (%d/2) PASSED!!\n", ++test_num);
  }

  return 0;

fail:
  printf("TEST FAILED!!\n");
  return 1;
}

int main(void) { 
  printf("---------------------------------------------\n");
  test1();
  printf("---------------------------------------------\n");
  test2(); 
  printf("---------------------------------------------\n");
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

