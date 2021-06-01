#include "Enclave_t.h"
#include "sg.h"
#include <string.h>

sg_ctx_t sg_ctx;

void initialize_sg() { init_sg(&sg_ctx); }

void connect_sg() {}

int generate_random_number() {
  ocall_print("Processing random number generation...");
  return 42;
}

/*
int generate_random_number() {
    ocall_print("Processing random number generation...");

    char test2[] = "/opt/instance/sg.db";

    int x = strlen(test2);
    ocall_print("Test\n");

   char test[1023];
   memcpy(test2, test, 10);
   test[10] = '\0';

    ocall_print("Here\n");

 //   init_sg(&sg_ctx, "test.txt");

    return 42;
}
*/
