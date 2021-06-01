#include "sg.h" 
#include "librassl/attester.h"
#include "sg_common.h"
#include "sg_t.h" //ocalls
#include "sg_util.h"
#include "wolfssl_enclave.h"

const char *cluster_hosts[] = {"mantou.rcs.uwaterloo.ca", "baguette.rcs.uwaterloo.ca", "tortilla.rcs.uwaterloo.ca"};

int connect_cluster_sg(sg_ctx_t *ctx) 
{
  init_ratls_server(&ctx->ratls, &ctx->kc);

  // Loop through the list of hosts and store connection information
  // for each
}


