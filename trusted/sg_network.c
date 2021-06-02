#include "librassl/attester.h"
#include "ra_tls.h"
#include "sg.h"
#include "sg_common.h"
#include "sg_t.h" //ocalls
#include "sg_util.h"
#include "wolfssl_enclave.h"

#define DEBUG_SG 1

struct connection {
  int ignore; // Ignore this entry when iterating
  int flag;
  int retries;
  ratls_ctx_t ratls;
  char hostname[128];
};

struct connection cluster_connections[3];
int num_hosts = 3;

static void gethostname(char *hostname) {
  sgx_status_t status = ocall_gethostname(hostname);
  if (status != SGX_SUCCESS) {
    eprintf("\t+ (%s) FAILED\n", __FUNCTION__);
    exit(1);
  }
  for (int i=0; i<128; ++i) {
    if (hostname[i] == '\0') return;
  }
  exit(1);
}

static void init_connection(struct connection *c, const char *hostname) { 
  c->retries = 2; 
  strcpy(c->hostname, hostname);
}

/* init_connections_sg : set retry count and flags for all connections
 * @param ctx Unused
 */
void init_connections_sg(sg_ctx_t *ctx) {
  char hostname[128];
  const char *cluster_hosts[] = {"mantou.rcs.uwaterloo.ca",
                                 "baguette.rcs.uwaterloo.ca",
                                 "tortilla.rcs.uwaterloo.ca"};

  gethostname(hostname);

#ifdef DEBUG_SG
  eprintf("\t+ (%s) This host is %s\n", __FUNCTION__, hostname);
#endif

  memset(cluster_connections, 0, sizeof(struct connection) * num_hosts);
  for (int i = 0; i < num_hosts; ++i) {
    if (strcmp(hostname, cluster_hosts[i]) == 0) {
      cluster_connections[i].ignore = 1;
    }
    init_connection(&cluster_connections[i], cluster_hosts[i]);
  }
}

int recieve_cluster_connections_sg(sg_ctx_t *ctx) {
  int ret;
  int sofar = 0;

  while (sofar < num_hosts) {

    int sockfd = 0;
    // TODO: write this function
    ret = accept_cluster_connections_sg(&ctx->ratls, NULL);
  }
}

/* connect_cluster_sg
 * @param ctx Initialized sg_ctx_t
 * @return 1 on error, 0 on success
 */
int connect_cluster_sg(sg_ctx_t *ctx) {
  int ret;
  int sofar = 0;
  int retries_exhausted = 0;

#ifdef DEBUG_SG
  eprintf("\t+ (%s) Establishing connection to cluster\n", __FUNCTION__);
#endif

  while (!retries_exhausted && sofar != num_hosts - 1) {
    for (int i = 0; i < num_hosts; ++i) {
      if (!cluster_connections[i].flag || cluster_connections[i].retries ||
          !cluster_connections[i].ignore) {
        ret = init_ratls_client(&cluster_connections[i].ratls, &ctx->kc,
                                cluster_connections[i].hostname);
        if (ret) {
          if (--cluster_connections[i].retries == 0) {
            retries_exhausted = 1;
          }
#ifdef DEBUG_SG
          eprintf("\t+ (%s) Connection to %s failed. Retries left: %d\n",
                  __FUNCTION__, cluster_connections[i].hostname,
                  cluster_connections[i].retries);
#endif
        } else {
          cluster_connections[i].flag = 1;
          ++sofar;
        }
      }
    }
  }

  if (retries_exhausted) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) FAILED ... Exiting\n", __FUNCTION__);
#endif
    return 1;
  }
}

