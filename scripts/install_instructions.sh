#!/bin/bash

git submodule init
git submodule update

# Bearssl
cd deps/BearSSL && gmake CC="gcc48"
cd ..

# Protobuf (old version)
tar -xvf protobuf-c-1.3.3.tar.gz
mv protobuf-c-1.3.3 protobuf-c
patch -p1 < stef.patch  
cd protobuf-c && mkdir build && cd build && cmake -D CMAKE_C_COMPILER=gcc48 ../build-cmake && gmake
cd ../../..


# WolfSSL with SGX
touch deps/wolfssl/wolfssl/options.h
cp scripts/wolfssl/build_ratls.sh deps/wolfssl/IDE/LINUX-SGX/
patch -p1 -d deps/wolfssl < scripts/wolfssl/wolfssl.patch 
# When promted enter 'y'
# Ignore this: patch -p1 -d deps/wolfssl < scripts/wolfssl/wolfssl-sgx-attestation.patch 
cd deps/wolfssl/IDE/LINUX-SGX
./build_ratls.sh
cd -

# Patch tiny-regex-c so we can compile it in the enclave
patch -p1 -d deps/tiny-regex-c < scripts/patch_tiny_regex_sgx.patch


# Building the library (libsgtrusted.a & libsgtrusted.a)
cd lib/libsg
cd build && cmake .. && gmake

# Building the server application (linked against ^^)
cd ../../../server
cd build && cmake .. && gmake
sudo ./app

# Make sure kernel module is loaded and aesm service is running
sudo kldload sgx
cd /opt/intel/sgxpsw/aesm && sudo ./aesm_service 




