#!/usr/local/bin/bash


set -x

mkdir ../../lib/libsg/build
mkdir ../lib/libsgd/build

cd lib/libsg/build && rm -rf * && cmake .. && gmake
cd -


cd lib/libsgd/build && rm -rf * && cmake .. && gmake
cd -

cd build && rm -rf * && cmake .. && gmake

