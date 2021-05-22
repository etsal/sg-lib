#!/bin/bash

touch ../../deps/wolfssl/wolfssl/options.h
cp options.h ../../deps/wolfssl/wolfssl
cp build_ratls.sh ../../deps/wolfssl/IDE/LINUX-SGX

#patch -p1 -d ../../deps/wolfssl/ < wolfssl.patch 
#patch -p1 -d ../../deps/wolfssl/ < wolfssl-sgx-attestation.patch 


cd ../../deps/wolfssl/IDE/LINUX-SGX 
chmod +x build_ratls.sh
./build_ratls.sh

