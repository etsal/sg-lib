# Skeleton for FreeBSD NSS Module
This module contains the skeleton code for a FreeBSD NSS module that implments the following services :
 * getpwent_r
 * getpwuid_r
 * getpwnam_r
 * setpwent
 * endpwent

for the `passwd` db.

## Build & Install
    $(CC) -fPIC -shared -o nss_test.so.1 nss_test.c
    cp nss_test.so.1 /usr/lib
## Setup
Open `nsswitch.conf` and change the line

    passwd: compat

to

    passwd: test
## Test
Check if module is loaded

    getent passwd root

Verify the statements are printed.

# NSS Background
NSS offers modules that implement services (i.e., functions) that access certain databases. These databases include `passwd`, `group`, `hosts` ... etc. The `nsswitch.conf` file controls what service is used by a process to look up info in each database. The default services include `files`, `db`, `dns`, `nis`, and `nisplus`. These modules are traditionally implemented in the glibc library. The glibc functions that use the name services call the `_nsdispatch` function that reads the `nsswitch.conf` function on each invokation, and loads the correct shared library that implements the correct services.

For example, the following entry in `nsswitch.conf` 
    
    passwd: ldap
    
will search for the nss_ldap.so.1 module. This module must implement the services available for the `passwd` database. Furthermore, FreeBSD requries a module register function to be implemented. For more info see [link](https://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html/).
