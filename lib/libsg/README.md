Important structures

    typedef struct {
        key_cert_t kc;          // RA-TLS Keys and Cert
        ratls_ctx_t ratls;      // RA-TLS Context (WolfSSL Structures)
        db_ctx_t db;            // Database context
        configuration *config;  
    } sg_ctx_t

    typedef struct {
        uint8_t der_key[];
        uint8_t der_cert[];
        ...
    } key_cert_t;
----
    
    void init_sg(sg_ctx_t *ctx, void *config, size_t config_len)
1. Deserialize config into `struct configuration`. The config file was read and serialized by the App and passed into the Enclave.
2. Initialize logging.
3. Attempt to load/unseal an `key_cert_t` and `table_t` (in `db_ctx_t`). 
4. Upon failure, initialize a new `sg_ctx_t` structure with `init_new_sg()`.  

----
    void init_new_sg(sg_ctx_t *ctx)
1. Call `init_keycert()` which does the following:
a. Call `create_key_and_x509()`.
b. Generate RSA key with exponent e=65537 and bits len=3072.
c. Encode RSA key in DER format.
d. Hash (SHA256) the RSA key for the `report_data`.
e. Ocall to get `sgx_target_info_t`. Next call `sgx_create_report()` passing `sgx_target_info` and `report_data` to get `report`.
f. Send `report` to IAS and recieve `attestation_report` from IAS.
g. Create a self-signed X509 certificate with the DER encoded RSA key and `attestation_report`.
2. Call `init_new_db()` which does the following:
a. Initialize a new KV store context.

Note: The `db.*` files can be removed because they are simply a wrapper for funcs in `libstore`; which can be called directly from `sg.c`.

---
    int initiate_connections(sg_ctx_t *ctx);
1. Calls `init_ratls_client()` for each 'client connection' (i.e., node acting as a client for the communication).  
2. If successful, sends the name of the IP address to the 'server' to let the server know who is connected.
3. Optionally check if a 'client connection' has been established to all nodes in the system. 
Defined in `sg_network.c`. 
---
    int recieve_connections(sg_ctx_t *ctx);
1. In a loop, calls `accept_connections()` to accept connections from clients
2. On success, reads the IP address of the client (to determine what client has connected)
3. Initializes connection structure for this server->client
Defined in `sg_network.c`. 
---
    int init_ratls_client(ratls_ctx_t *ctx, key_cert_t *kc, const char *host)
 1. Call `host_connect()`
 2. Set client authentication is wolfssl ctx
 3. Call `wolfSSL_connect()`
 4. Verify the connection
 Defined in `sg_network.c`. 
