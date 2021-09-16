#!/bin/bash

#../../server/lib/libsgd

#-L../../../server/lib/libsgd/build -l:libsgd.a


gcc48 main.c -L../../../server/lib/libsgd/build/ -l:libsgd.a 

