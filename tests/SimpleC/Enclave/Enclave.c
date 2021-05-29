#include "Enclave_t.h"

#include "sg.h"

sg_ctx_t sg_ctx;

void initialize_sg(const char *filename) {
    init_sg(&sg_ctx, filename);
}

int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}
