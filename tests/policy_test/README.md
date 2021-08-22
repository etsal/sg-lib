# About the configuration file
Expect the `config.ini` file to contain the following:

    [network]
    num_nodes=N
    node1=xxx.xxx.xxx.xxx
    node2=xxx.xxx.xxx.xxx
    ...
    nodeN=xxx.xxx.xxx.xxx

Where `num_nodes` contains the number of nodes in the cluster. The host's IP address must be specified in a `nodeX` variable. The topology of the network forms a complete graph, with a mutually authenticated TLS/SSL connection between each node in the cluster. All nodes must connect before proceeding to send/recieve updates. 
