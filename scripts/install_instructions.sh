#!/usr/local/bin/bash

echo "Compiling dependencies. This script assumes it is called from the base of the repository."
BASEDIR=$PWD

git submodule init
git submodule update

# Bearssl
cd $BASEDIR/deps/BearSSL 
gmake CC="gcc48"

# Protobuf (old version)
cd $BASEDIR/deps/protobuf-c
mkdir build; cd build
cmake -D CMAKE_C_COMPILER=gcc48 ../build-cmake
gmake

# WolfSSL with SGX
cd $BASEDIR/deps/wolfssl/IDE/LINUX-SGX;
./build_ratls.sh

# Building the library (libsgtrusted.a & libsgtrusted.a)
cd $BASEDIR/lib/libsg
mkdir build; cd build 
cmake .. 
gmake

touch $BASEDIR/deps/wolfssl/wolfssl/options.h
cd $BASEDIR/server/lib/libsgd
mkdir build; cd build
cmake ..
gmake

# Building the server application (linked against ^^)
cd $BASEDIR/server
mkdir build; cd build
cmake ..
gmake
sudo ./app

# Make sure kernel module is loaded and aesm service is running
cd /opt/intel/sgxpsw/aesm && sudo ./aesm_service 
