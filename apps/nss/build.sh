#!/bin/bash

#gcc48 -fPIC -shared -o nss_test.so.1 test-pwd.c

gcc48 -fPIC -shared -o nss_test.so.1 test-pwd.c bsd-nss.c

