#include "Enclave_t.h"
#include <string.h>


void initialize_sg() {
    ocall_print("Running int_sg()\n");
//    init_sg(&sg_ctx, "Hello");
}

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
