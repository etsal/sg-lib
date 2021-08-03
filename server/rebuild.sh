#!/bin/bash

set -x

cd ../lib/libsg/build && gmake

cd -

cd build && rm -rf * && cmake .. && gmake

