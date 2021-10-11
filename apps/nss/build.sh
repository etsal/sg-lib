#!/bin/bash

#gcc48 -fPIC -shared -o nss_sg.so.1 nss_sg.c
#gcc48 -fPIC -shared -o nss_sg.so.1 -I../../server/lib/libsgd nss_sg.c 

#gcc48 -fPIC -shared -I../../server/lib/libsgd nss_sg.c -L../../server/lib/libsgd/build -l:libsgd.a -o nss_sg.so.1

cd build && gmake clean && gmake
cp nss_sg.so.1 /usr/lib
cd -

echo "Copied library .."

g++48 test.c

echo "getentpasswd root"
