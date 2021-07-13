#!/bin/bash
set -x

gcc48 -fPIC -fno-stack-protector -c pam_module.c 

sudo ld -x --shared -o /usr/lib/pam_example.so pam_module.o

