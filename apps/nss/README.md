# Skeleton for NSS Module
This module contains the skeleton code for a FreeBSD NSS module that implements the following services :
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
