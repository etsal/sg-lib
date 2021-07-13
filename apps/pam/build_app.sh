#!/bin/bash
set -x

# Build and install module
gcc48 -fPIC -fno-stack-protector -c pam-module/pam_module.c

sudo ld -x --shared -o /usr/lib/pam_example.so pam_module.o

gcc48 -o run_pam.o -std=c99 pam-app/pam_app.c -lpam
