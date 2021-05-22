#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "../kvcrdt.h"
#include "../vvec.h"
#include "../../../common/sg_common.h"

int main() 
{
    setvbuf(stdout, NULL, _IONBF, 0);

    kvcrdt_table_t set1, set2;
    
    uint64_t replica_id = 1;
    uint64_t replica_id2 = 2;

    init_kvcrdt(&set1, replica_id);
    init_kvcrdt(&set2, replica_id2);

    char alice[] = "alice";
    char bob[] = "bob";

    // Modifying set
    add_kvcrdt(&set1, 1, alice, strlen(alice));
    add_kvcrdt(&set1, 2, bob, strlen(bob));
    remove_kvcrdt(&set1, 2);

    // Modifying set2
    add_kvcrdt(&set2, 1, alice, strlen(alice));
    add_kvcrdt(&set2, 2, bob, strlen(bob));

    printf("Set 1\n");
    print_kvcrdt(&set1);
    printf("\n");

    printf("Set 2\n");
    print_kvcrdt(&set2);
    printf("\n");

    // Merge
    printf("Merging Set 2 into Set 1\n");
    merge_kvcrdt(&set1, &set2);
    
    printf("Set 1\n");
    print_kvcrdt(&set1);
    printf("\n");

    // Serialize
    uint8_t *buf;
    size_t len;

    printf("Serializing Set 1\n");
    serial_kvcrdt(&set1, &buf, &len);
    printf("Serialized data: %s\n", hexstring(buf, len));

    deserial_kvcrdt(&set2, buf, len);

    printf("Deserialized Set 1\n");
    print_kvcrdt(&set2); 

    free(buf);
    free_kvcrdt(&set1);
    free_kvcrdt(&set2);

    printf("done\n");
}

