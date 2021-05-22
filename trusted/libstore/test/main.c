#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "../store.h"
#include "../vvec.h"
#include "../../../common/sg_common.h"

int main() 
{
    setvbuf(stdout, NULL, _IONBF, 0);

    table_t set1, set2, set3;
    
    uint64_t replica_id     = 1;
    uint64_t replica_id2    = 2;
    uint64_t replica_id3    = 3;

    init_store(&set1, replica_id);
    init_store(&set2, replica_id2);
    init_store(&set3, replica_id3);

    char alice[] = "alice@gmail.com";
    char bob[] = "bob@gmail.com";

    // Modifying set
    put_store(&set1, "/usr/alice", alice, strlen(alice));
    put_store(&set1, "/usr/bob", bob, strlen(bob));
    //remove_kvcrdt(&set1, "/usr/bob");

    printf("Set 1\n");
    print_store(&set1);
    printf("\n");

    // Modifying set2
    put_store(&set2, "/usr/alice", alice, strlen(alice));
    put_store(&set2, "/usr/bob", bob, strlen(bob));

    printf("Set 2\n");
    print_store(&set2);
    printf("\n");
/*
    // Merge
    printf("Merging Set 2 into Set 1\n");
    merge_kvcrdt(&set1, &set2);
    
    printf("Set 1\n");
    print_kvcrdt(&set1);
    printf("\n");
*/
    // Serialize
    uint8_t *buf;
    size_t len;

    printf("Serializing Set 1\n");
    serialize_store(&set1, &buf, &len);
    printf("Serialized data: %s\n", hexstring(buf, len));

    deserialize_store(&set3, buf, len);

    printf("Deserialized Set 1 into Set 3\n");
    print_store(&set3); 

    free(buf);

    free_store(&set1);
    free_store(&set2);
    free_store(&set3);

    printf("Done!\n\n");
}

