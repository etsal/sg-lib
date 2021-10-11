# NSS Module

This module contains the skeleton code for a FreeBSD NSS module that implments the following services :
 * getpwent_r *
 * getpwuid_r
 * getpwnam_r
 * setpwent *
 * endpwent *

for the `passwd` db.

# Background
Functions make a IPC call to the daemon found in ```../../server```. Server must be running for these functions to succeed.

# To Build
    mkdir build && cd build && cmake .. && gmake
    
# To Install
1. Open `nsswitch.conf` and change the line ```passwd: compat``` to ```passwd: sg```
2. Run the following: ```cp build/nss.so.lib.1 /usr/lib```

# Quick Test
1. Run the following: ```pwgetent passwd <user>```
2. Run the following: ```CC test.c && ./a.out <user>```
