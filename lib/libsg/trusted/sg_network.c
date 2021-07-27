#include "sgx_thread.h"
#include <assert.h>
#include <sys/limits.h>

#include "librassl/attester.h"
#include "ra_tls.h"
#include "sg.h"
#include "sg_common.h"
#include "sg_messages.h"
#include "sg_t.h" //ocalls
#include "sg_util.h"
#include "wolfssl_enclave.h"
#define DEBUG_SG 1

struct connection {
  int ignore; // Ignore this entry when iterating
  int flag;
  int retries;
  ratls_ctx_t ratls;
  sgx_thread_mutex_t lock;
  char hostname[128];
};

struct connection client_connections[3];
struct connection server_connections[3];

int num_hosts = 3;
int pollUpdatesFlag = 1;

static void gethostname(char *hostname) {
  sgx_status_t status = ocall_gethostname(hostname);
  if (status != SGX_SUCCESS) {
    eprintf("\t+ (%s) FAILED\n", __FUNCTION__);
    exit(1);
  }
  for (int i = 0; i < 128; ++i) {
    if (hostname[i] == '\0')
      return;
  }
  exit(1);
}

static struct connection *find_connection(const char *hostname,
                                          struct connection c[]) {
  for (int i = 0; i < num_hosts; ++i) {
    if (strcmp(c[i].hostname, hostname) == 0)
      return &c[i];
  }
  return NULL;
}

static void init_connection(struct connection *c, const char *hostname) {
  c->retries = 0;
  strcpy(c->hostname, hostname);
  sgx_thread_mutex_init(&c->lock, NULL);
}

static void init_connections_(sg_ctx_t *ctx, struct connection c[]) {
  char hostname[128];
  const char *cluster_hosts[] = {"mantou.rcs.uwaterloo.ca",
                                 "baguette.rcs.uwaterloo.ca",
                                 "tortilla.rcs.uwaterloo.ca"};
  gethostname(hostname);

#ifdef DEBUG_SG
//  eprintf("\t+ (%s) This host is %s\n", __FUNCTION__, hostname);
#endif

  memset(c, 0, sizeof(struct connection) * num_hosts);
  for (int i = 0; i < num_hosts; ++i) {
    if (strcmp(hostname, cluster_hosts[i]) == 0) {
      c[i].ignore = 1;
    }
    init_connection(&c[i], cluster_hosts[i]);
  }
}

/* init_connections_sg()
 * Initializes connection structures
 * Remember to set retry count and flags for all connections
 * @param ctx Unused
 */
void init_connections(sg_ctx_t *ctx) {
  init_connections_(ctx, client_connections);
  init_connections_(ctx, server_connections);
}

static int push_msg_sg(sg_ctx_t *ctx, const char *msg) {
  uint8_t *update;
  size_t update_len = 0;
  int ret;
  uint32_t len;
  /*
    db_get_update_len(&ctx->db, &update_len);
    if (!update_len) {
  #ifdef DEBUG_SG
      eprintf("\t+ (%s) ERROR : Update is of length %d\n", __FUNCTION__,
              update_len);
  #endif
      return 1;
    }
    update = malloc(update_len);
    db_get_update(&ctx->db, update, update_len);
  */

  update = malloc(strlen(msg) + 1);
  for (int i = 0; i < strlen(msg); ++i)
    update[i] = msg[i];
  update[strlen(msg)] = '\0';
  update_len = strlen(msg) + 1;

  for (int i = 0; i < num_hosts; ++i) {
    if (client_connections[i].ignore)
      continue;

    ret = prepare_and_send_updates(&client_connections[i].ratls, update,
                                   update_len);
    if (ret) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) ERROR : Failed to send update to %s\n", __FUNCTION__,
              client_connections[i].hostname);
#endif
      exit(1);
      // break;
    }
  }

  free(update);
  return 0;
}

int send_msg_sg(sg_ctx_t *ctx, const char *msg) {
  return push_msg_sg(ctx, msg);
}

/* process_update_sg()
 * Called by poll_and_process_updates() to read from the socket
 * Calls read_ratls() -calls-> enc_wolfSSL_read() which uses a ocall callback to
 * read from the socket locks db and applies update
 */

/* verify_cluster_connections_sg()
 * Verifies that we have an active connection with each node
 * in the cluster
 */
int verify_connections_sg(sg_ctx_t *ctx) {
  int max_ignore = 0;

  for (int i = 0; i < num_hosts; ++i) {
    if (!((!client_connections[i].ignore && client_connections[i].flag))) {
      if (max_ignore++ > 1) {
#ifdef DEBUG_SG
        eprintf("\t+ (%s) FAILED @ %s\n", __FUNCTION__,
                client_connections[i].hostname);
#endif
        return 0;
      }
    }
  }

  max_ignore = 0;
  for (int i = 0; i < num_hosts; ++i) {
    if (!((!server_connections[i].ignore && server_connections[i].flag))) {
      if (max_ignore++ > 1) {
#ifdef DEBUG_SG
        eprintf("\t+ (%s) FAILED @ %s\n", __FUNCTION__,
                server_connections[i].hostname);
#endif
        return 0;
      }
    }
  }
  return 1;
}

/* push_updates_sg
 * Sends the size of the updates and then the update itself
 * Recieiving end must follow this order
 */
int push_updates_sg(sg_ctx_t *ctx) {
  uint8_t *update;
  size_t update_len = 0;
  int ret;
  uint32_t len;

  db_get_update_len(&ctx->db, &update_len);
  if (!update_len) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) ERROR : Update is of length %d\n", __FUNCTION__,
            update_len);
#endif
    return 1;
  }
  update = malloc(update_len);
  db_get_update(&ctx->db, update, update_len);

  for (int i = 0; i < num_hosts; ++i) {
    if (client_connections[i].ignore)
      continue;

    ret = prepare_and_send_updates(&client_connections[i].ratls, update,
                                   update_len);
    if (ret) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) ERROR : Failed to send update to %s\n", __FUNCTION__,
              client_connections[i].hostname);
#endif
      exit(1);
      // break;
    }
  }

  free(update);
  return 0;
}

/* poll_for_updates()
 * Loops calling ocall_select to recieve and process messages
 */
int poll_and_process_updates_sg(sg_ctx_t *ctx) {
  // To track connection <-> fd to make it easier to find
  // connection when ocall_select returns
  struct fd_connection_map {
    int sockfd;
    struct connection *c;
  };

  struct fd_connection_map m[2];
  int active_fds[num_hosts];
  int check_fds[num_hosts];

  int ret;

  // Gather sockfds and initialize select
  int j = 0;
  for (int i = 0; i < num_hosts; ++i) {
    if (server_connections[i].ignore) {
      // continue;
      active_fds[i] = 0; // SGX will not copy  INT_MAX / -1 properly
    } else {

      // This connection is set (flag) and not to ourselves (ignore)
      if (!(!server_connections[i].ignore && server_connections[i].flag)) {
#ifdef DEBUG_SG
        eprintf("\t+ (%s) Error, cannot recieve updates from host %s)\n",
                __FUNCTION__, server_connections[i].hostname);
#endif
        // return 1;
      }

      active_fds[i] = server_connections[i].ratls.sockfd;
      m[j].sockfd = active_fds[i];
      m[j].c = &server_connections[i];
      ++j;
    }
  }

  // Print sockets
#ifdef DEBUG_SG
  eprintf("\t+ active set of fds: ");
  for (int i = 0; i < num_hosts; ++i) {
    eprintf("%d ", active_fds[i]);
  }
  eprintf("\n");
#endif

  while (pollUpdatesFlag) {
    // ocall_poll_and_process_updates(&ret, active_fds, num_hosts);
    ocall_poll_and_process_updates(&ret, active_fds, check_fds, num_hosts);

    for (int i = 0; i < num_hosts; ++i) {
      if (check_fds[i] == 0)
        continue;
#ifdef DEBUG_SG
      eprintf("\t+ (%s) incoming message from host %s\n", __FUNCTION__,
              server_connections[i].hostname);
#endif
      process_message(&server_connections[i].ratls);

      /*
            uint8_t buf[1024];
            size_t buf_len = 1023;

            memset(buf, 0, sizeof(buf));
            read_ratls(&server_connections[i].ratls, buf, buf_len);
            eprintf("Read: -->%s<--\n", hexstring(buf, buf_len));
      */
    }
  }
}

/* recieve_connections_sg()
 * Will continue looping until all connections are made
 * @param ctx Initialized sg_ctx_t
 * @return 1 on error, 0 on success
 */
int recieve_connections_sg(sg_ctx_t *ctx) {
  int ret;
  int connections_sofar = 0;
  // char hostname[128];
  char client_hostname[128];
  struct connection *c;
  ratls_ctx_t client;

  // Get hostname
  //  gethostname(hostname);

  while (connections_sofar < num_hosts - 1) {
    int sockfd = 0;

#ifdef DEBUG_SG
    eprintf("\t+ (%s) Listening for connections from cluster\n", __FUNCTION__);
#endif
    ret = accept_connections(&ctx->ratls, &client);
    if (ret) {
      continue;
    }

    // Read client_hostname
    read_ratls(&client, client_hostname, 128);

#ifdef DEBUG_SG
    eprintf("\t+ (%s) Accepted client connection from %s\n", __FUNCTION__,
            client_hostname);
#endif

    /* OLD
    // Loop through list comparing client_hostname, once you find the
    // respective object, then check if the lock is held. If it is, then
    // connect_cluster_sg is holding it so wait until unlocked to check the
    // flag if the connection was successful from that direction, otherwirse,
    // we have a successful connection so lets not close it
    // Find the client_hostname in our connections list

    c = find_connection(client_hostname);
    if (c == NULL) {
      cleanup_ratls(&client);
#ifdef DEBUG_SG
      eprintf("\t+ (%s) Closing connection from %s\n", __FUNCTION__,
              client_hostname);
#endif
      continue;
    }
    */

    c = find_connection(client_hostname, server_connections);
    if (c == NULL) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) Connection struct for %s not initialized\n",
              __FUNCTION__, client_hostname);
#endif
      exit(1);
    }

    memcpy(&c->ratls, &client,
           sizeof(ratls_ctx_t)); // Non-nested structure so we are ok
    c->flag = 1;
    ++connections_sofar;
  }

  return 0;
}

/* initiate_connections_sg
 * Will continue looping until all connections are made
 * @param ctx Initialized sg_ctx_t
 * @return 1 on error, 0 on success
 */
int initiate_connections_sg(sg_ctx_t *ctx) {
  int ret;
  int connections_sofar = 0;
  int retries_exhausted = 0;
  char hostname[128];

  gethostname(hostname);

#ifdef DEBUG_SG
  // eprintf("\t+ (%s) Establishing connection to cluster\n", __FUNCTION__);
#endif

  while (connections_sofar != num_hosts - 1) {

    ocall_sleep(1);

    for (int i = 0; i < num_hosts; ++i) {
      if (!client_connections[i].flag && !client_connections[i].ignore) {
        ret = init_ratls_client(&client_connections[i].ratls, &ctx->kc,
                                client_connections[i].hostname);
        if (ret) {
          ++client_connections[i].retries;
#ifdef DEBUG_SG
          eprintf("\t+ (%s) Connection to %s failed. Retry count: %d\n",
                  __FUNCTION__, client_connections[i].hostname,
                  client_connections[i].retries);
#endif
        } else {
          client_connections[i].flag = 1;
          ++connections_sofar;
#ifdef DEBUG_SG
          eprintf("\t+ (%s) Connection to %s successful!\n", __FUNCTION__,
                  client_connections[i].hostname);
#endif
          write_ratls(&client_connections[i].ratls, hostname, 128);
        }
      } // if
    }   // for
  }     // while

  /*
    if (retries_exhausted) {
  #ifdef DEBUG_SG
      eprintf("\t+ (%s) FAILED ... Exiting\n", __FUNCTION__);
  #endif
      //cleanup_connections_sg();
      return 1;
    }
  */

  return 0;
}

static void close_connections(struct connection c[]) {
  for (int i = 0; i < num_hosts; ++i) {
    if (c[i].flag) { // Only cleanup structs that represent a successful
                     // connection (maybe do all?)
#ifdef DEBUG_SG
      eprintf("\t+ (%s) Cleaning up connection to %s\n", __FUNCTION__,
              c[i].hostname);
#endif
      cleanup_ratls(&c[i].ratls);
    }
  }
}

void cleanup_connections_sg() {
  close_connections(client_connections);
  close_connections(server_connections);
}
