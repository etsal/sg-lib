#include <assert.h>
#include <sys/limits.h>

#include <sgx_thread.h>

#include "librassl/attester.h"
#include "ra_tls.h"
#include "sg.h"
#include "sg_common.h"
#include "sg_messages.h"
#include "sg_stdfunc.h"
#include "sg_util.h"
#include "wolfssl_enclave.h"

#include "networking_t.h"
#include "stdfunc_t.h"

#define DEBUG_SG 1
#define INET6_ADDRSTRLEN 46 /* copied from <arpa/inet.h> */

/* Keep a global array of client->server
 * and server-> client connections
 *
 */
struct connection {
  int ignore; // Ignore this struct when iterating
  int is_connected;
  int retries;
  ratls_ctx_t ratls;
  char hostname[128];
  char ip[INET6_ADDRSTRLEN];
};

struct connection *client_connections[MAX_NODES];
struct connection *server_connections[MAX_NODES];

int num_hosts = 0;
int pollUpdatesFlag = 1;

static void prettyprint_connection(struct connection *c) {
  edividerWithText("Connection");
  eprintf("Ignore -> %d\n", c->ignore);
  eprintf("Hostname -> %s\n", c->hostname);
  eprintf("IP -> %s\n", c->ip);
  edivider();
}

static void prettyprint_connections() {
  edividerWithText("Client Connections");
  for (int i = 0; i < num_hosts; ++i)
    prettyprint_connection(client_connections[i]);

  edividerWithText("Server Connections");
  for (int i = 0; i < num_hosts; ++i)
    prettyprint_connection(server_connections[i]);
}

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

static void gethostip(char *ip) {
  sgx_status_t status = ocall_gethostip(ip);
  if (status != SGX_SUCCESS) {
    exit(1);
  }
}

static struct connection *find_connection(const char *ip,
                                          struct connection **c) {
  for (int i = 0; i < num_hosts; ++i) {
    if (strcmp(c[i]->ip, ip) == 0)
      return c[i];
  }
  return NULL;
}

static struct connection *find_connection_with_fd(int fd,
                                                  struct connection **c) {
  for (int i = 0; i < num_hosts; ++i) {
    if (c[i]->ratls.sockfd == fd)
      return c[i];
  }
  return NULL;
}

void set_uid(sg_ctx_t *ctx) {
  char **hostips;
  char ip[INET6_ADDRSTRLEN];
  int i;
  num_hosts = ctx->config->found_ips;
  hostips = (char **)ctx->config->ips;
  gethostip(ip);
  if (num_hosts == 0) {
    ctx->uid = 1;
    return;
  }
  for (i = 0; i < num_hosts; ++i) {
    if (strcmp(ip, hostips[i]) == 0) {
      ctx->uid = i + 1;
      return;
    }
  }
  ctx->uid = -1;
}

/* init_connections_sg()
 * Initializes connection structures
 * TODO:Remember to set retry count and flags for all connections
 * @param ctx Unused
 */
void init_connections(sg_ctx_t *ctx) {
  char hostname[128];
  char ip[INET6_ADDRSTRLEN];
  char **hostips;

  gethostname(hostname);
  gethostip(ip);

  num_hosts = ctx->config->found_ips;
  assert(num_hosts != 0 && num_hosts < MAX_NODES);

#ifdef DEBUG_SG
  eprintf("\t+ (%s) This host is %s - %s out of %d other hosts\n", __FUNCTION__,
          hostname, ip, num_hosts);
#endif

  // Run server without connection to other nodes
  if (num_hosts == 1) {
    num_hosts = 0;
    return;
  }

  hostips = (char **)ctx->config->ips;

  // We create 1 extra connection structure here, but ohwell
  for (int i = 0; i < num_hosts; ++i) {
    client_connections[i] = malloc(sizeof(struct connection));
    server_connections[i] = malloc(sizeof(struct connection));
    memset(client_connections[i], 0, sizeof(struct connection));
    memset(server_connections[i], 0, sizeof(struct connection));
  }

  int j = 0;
  for (int i = 0; i < num_hosts; ++i) {
    if (strcmp(ip, hostips[i]) != 0) {
#ifdef DEBUG_SG
      eprintf("\t\t + other node is: %s\n", hostips[i]);
#endif
      client_connections[j]->retries =
          0; // Set retries here can be done with ctx->config->retries
      server_connections[j]->retries =
          0; // Set retries here can be done with ctx->config->retries
      strcpy(client_connections[j]->ip,
             hostips[i]); //, strlen(hostips[i]) + 1);
      strcpy(server_connections[j]->ip, hostips[i]); // strlen(hostips[i]) + 1);
      ++j;
    }
  }

  num_hosts = j; // Number of initialized hosts

#ifdef DEBUG_SG
  eprintf("\t\t + number of hosts: %d\n", num_hosts);
#endif
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
    if (client_connections[i]->ignore)
      continue;

    ret = prepare_and_send_updates(&client_connections[i]->ratls, update,
                                   update_len);
    if (ret) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) ERROR : Failed to send update to %s\n", __FUNCTION__,
              client_connections[i]->hostname);
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
  for (int i = 0; i < num_hosts; ++i) {
    if (!client_connections[i]->is_connected) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) FAILED @ %s\n", __FUNCTION__,
              client_connections[i]->ip);
#endif
      return 0;
    }
  }

  for (int i = 0; i < num_hosts; ++i) {
    if (!server_connections[i]->is_connected) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) FAILED @ %s\n", __FUNCTION__,
              server_connections[i]->ip);
#endif
      return 0;
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

  update_len = get_update_size(ctx);
  if (!update_len) {
#ifdef DEBUG_SG
    eprintf("+ (%s) ERROR : Update is of length %d\n", __FUNCTION__,
            update_len);
#endif
    return 1;
  }

  update = malloc(update_len);
  if (update == NULL) {
    eprintf("+ (%s) malloc failed\n", __FUNCTION__);
    return 1;
  }
  get_update(ctx, update, update_len);

  int i;
  for (i = 0; i < num_hosts; ++i) {

    if (client_connections[i]->ignore)
      continue;

    ret = prepare_and_send_updates(&client_connections[i]->ratls, update,
                                   update_len);
    if (ret) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) ERROR : Failed to send update to %s\n", __FUNCTION__,
              client_connections[i]->hostname);
#endif
      exit(1);
      // break;
    }
  }
  free(update);
  return 0;
}

/*
 * Fills fds in with server_connection fds
 */
void get_connection_fds(int *fds, size_t max_len, size_t *len) {

  int i; // j = 0;

  if (max_len < num_hosts) {
    *len = 0;
    return;
  }

  for (i = 0; i < num_hosts; ++i) {
    if (server_connections[i]->ignore) {
      fds[i] = 0; // SGX will not copy  INT_MAX / -1 properly
    } else {
      // This connection is set (flag) and not to ourselves (ignore)
      if (!(!server_connections[i]->ignore &&
            server_connections[i]->is_connected)) {
#ifdef DEBUG_SG
        eprintf("\t+ (%s) Error, cannot recieve updates from host %s)\n",
                __FUNCTION__, server_connections[i]->hostname);
#endif
        // return 1;
      }

      fds[i] = server_connections[i]->ratls.sockfd;
      // m[j].sockfd = active_fds[i];
      // m[j].c = server_connections[i];
      //++j;
    }
  }
  *len = num_hosts;

  // Print sockets
#ifdef DEBUG_SG
  eprintf("\t+ (%s) active set of fds:\n", __FUNCTION__);
  for (int i = 0; i < num_hosts; ++i) {
    eprintf("\t\t sockfd = %d\n", fds[i]);
  }
#endif
}

/* For each fd in the array, find it in the server_connections array
 * and call process_message on that connection
 */
void process_updates_sg(sg_ctx_t *ctx, int *fds, size_t len) {
  struct connection *conn;
  uint8_t *buf = NULL;
  size_t buf_len;
  int ret, i, type;

  eprintf("+ (%s) len = %d\n", __FUNCTION__, len);

  for (i = 0; i < len; ++i) {
    conn = find_connection_with_fd(fds[i], server_connections);
    if (conn == NULL) {
#ifdef DEBUG_SG
      eprintf("+ (%s) Failed to find server connection fd = %d\n", __FUNCTION__,
              fds[i]);
#endif
      // connection not found
      continue;
    }

#ifdef DEBUG_SG
    eprintf("+ (%s) Calling recieve_message() ...\n", __FUNCTION__);
#endif

    ret = receive_message(&conn->ratls, &type, &buf, &buf_len);
    switch(type) {
      case HEARTBEAT:
        break;
      case INCOMING:
#ifdef DEBUG_SG
        eprintf("+ (%s) Recieved INCOMING message\n", __FUNCTION__);
        // buf should contain serialized store
#endif
      break;
      default:
        break;
    }
    if (buf != NULL) free(buf);
  }
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
    if (server_connections[i]->ignore) {
      // continue;
      active_fds[i] = 0; // SGX will not copy  INT_MAX / -1 properly
    } else {

      // This connection is set (flag) and not to ourselves (ignore)
      if (!(!server_connections[i]->ignore &&
            server_connections[i]->is_connected)) {
#ifdef DEBUG_SG
        eprintf("\t+ (%s) Error, cannot recieve updates from host %s)\n",
                __FUNCTION__, server_connections[i]->hostname);
#endif
        // return 1;
      }

      active_fds[i] = server_connections[i]->ratls.sockfd;
      m[j].sockfd = active_fds[i];
      m[j].c = server_connections[i];
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
              server_connections[i]->hostname);
#endif
      //process_message(&server_connections[i]->ratls);

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
 * 1. Calls accept_connections to get a ra_tls_ctx_t for the client
 * 2. After connectiong, the client will send it's IP address
 * @param ctx Initialized sg_ctx_t
 * @return 1 on error, 0 on success
 */
int recieve_connections_sg(sg_ctx_t *ctx) {
  int ret;
  int connections_sofar = 0;
  // char hostname[128];
  char client_hostname[128];
  char client_ip[INET6_ADDRSTRLEN];
  struct connection *c;
  ratls_ctx_t client;

  // Get hostname
  //  gethostname(hostname);

  while (connections_sofar != num_hosts) {
    int sockfd = 0;

#ifdef DEBUG_SG
    eprintf("\t+ (%s) Listening for connections from cluster\n", __FUNCTION__);
#endif
    ret = accept_connections(&ctx->ratls, &client);
    if (ret) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) Failed to accept connection (0x%x)\n", __FUNCTION__,
              ret);
#endif
      continue;
    }

    // Read message from client (it should be the hostname)
    read_ratls(&client, client_ip, INET6_ADDRSTRLEN);

#ifdef DEBUG_SG
    eprintf("\t+ (%s) Accepted client connection from %s\n", __FUNCTION__,
            client_ip);
#endif

    c = find_connection(client_ip, server_connections);
    if (c == NULL) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) Connection struct for %s not initialized\n",
              __FUNCTION__, client_hostname);
#endif
      exit(1);
    }

    memcpy(&c->ratls, &client, sizeof(ratls_ctx_t));
    c->is_connected = 1;
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
  int retries = 0; // this is global retries it should be one per node
  int i;
  char hostname[128];
  char ip[INET6_ADDRSTRLEN];

  gethostname(hostname);
  gethostip(ip);

  while (connections_sofar != num_hosts) {
    ocall_sleep(1);

    for (i = 0; i < num_hosts; ++i) {
      if (!client_connections[i]->is_connected) {

#ifdef DEBUG_SG
        eprintf("\t+ (%s) Establishing connection to %s\n", __FUNCTION__,
                client_connections[i]->ip);
#endif
        ret = init_ratls_client(
            &client_connections[i]->ratls, &ctx->kc,
            client_connections[i]->ip); // CHANGED from hostname

        if (ret) {
#ifdef DEBUG_SG
          eprintf(
              "\t+ (%s) Connection to %s failed with 0x%x. Retry count: %d\n",
              __FUNCTION__, client_connections[i]->ip, ret, retries);
          // client_connections[i].retries)
#endif

          ++retries;
        } else {
#ifdef DEBUG_SG
          eprintf("\t+ (%s) Connection to %s successful!\n", __FUNCTION__,
                  client_connections[i]->ip);
#endif

          client_connections[i]->is_connected = 1;
          ++connections_sofar;
          write_ratls(&client_connections[i]->ratls, ip, INET6_ADDRSTRLEN);
        } // else
      }   // if
    }     // for
  }       // while

/*
  if (retries == 2) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) Failed to connect to all hosts ... exiting\n",
            __FUNCTION__);
#endif
    cleanup_connections_sg();
    return 1;
  }
*/
#ifdef DEBUG_SG
  eprintf("\t+ (%s) Successfully connected to all hosts\n", __FUNCTION__);
#endif

  return 0;
}

static void close_connections(struct connection **c) {
  for (int i = 0; i < num_hosts; ++i) {
    if (c[i] == NULL)
      return; // If we encounter a null connection, than it has already been
              // cleaned up
    if (c[i]->is_connected) { // Only cleanup structs that represent a
                              // successful connection (maybe do all?)
#ifdef DEBUG_SG
      eprintf("\t+ (%s) Cleaning up connection to %s\n", __FUNCTION__,
              c[i]->hostname);
#endif
      cleanup_ratls(&c[i]->ratls);
    }
    free(c[i]);
    c[i] = NULL;
  }
}

void cleanup_connections_sg() {
  close_connections(client_connections);
  close_connections(server_connections);
}
