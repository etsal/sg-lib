#!/bin/bash


cd lib/libsg/build && cmake .. && gmake
cd -

cd server/lib/libsgd/build && cmake .. && gmake
cd -

cd server/build && gmake clean && cmake .. && gmake
cd -

cd clients/build && gmake clean && cmake .. && gmake
cd -

