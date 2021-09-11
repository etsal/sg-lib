#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "../policy.h"
#include "../../../common/sg_common.h"


char *test1_policies[] = {
    "put:/u2f/stef/.+:stef",
    "get:/u2f/stef/.+:stef"
};

int main() 
{

    policy_ctx_t p;
    p.policies = test1_policies;
    p.len = 2;

    char *action_1 = generate_action("put", "/u2f/stef/facebook.com/stef666@hotmail.com", "stef");
    char *action_2 = generate_action("put", "/u2f/stef/facebook.com", "bob");


    int ret = validate_action(&p, action_1);
    printf("%s validated\n\taction : %s\n", ret?"Successfully":"Failed to", action_1);

    ret = validate_action(&p, action_2);
    printf("%s validated\n\taction : %s\n", ret?"Successfully":"Failed to", action_2);


    free(action_1);
    free(action_2);

    printf("Done!\n\n");
}

