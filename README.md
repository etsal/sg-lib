# SG: A Secure Distributed Key-Value Store

This repository contains code for a secure distributed key-value store designed to handle disconnected updates without consensus. We use Intel SGX to maintain data confidentiality and integrity, while remaining highly available with our use of conflict-free replicated data types (CRDTs). Additionally, we implement an access control layer directly ontop of the key-value store that authenticates users to the key-value store and authorizes operations. By emphasizing security and availability, and relaxing consistency we present a storage system that is attractive for applications on networks with sub-par connectivity.  We have implemented a decentralized replacement for LDAP user authentication using NSS and PAM modules and a replicable U2F security token.

They key-value store is implememented as a library that can be linked against SGX applications. With this we have developed a standalone daemon that runs an instance of the key-value store that synchronizes with other replicas and processes local API requests through Unix domain sockets.  

# Layout
 * ```apps/``` contains the applications built using SG
 * ```libs/``` contains the SG system built as a library
 * ```server/``` contains a daemon implementation 
 * ```client/``` contains CL programs that make API requests to the daemon
 * ```deps/``` contains dependencies

# Build
See BUILD.md for instructions. 

