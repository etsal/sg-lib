#!/bin/bash

set -x

DEPS_DIR=../../deps

#cp ../../lib/libsg/untrusted/config.* .

gcc48 -Wall -I${DEPS_DIR} main.c config.c ${DEPS_DIR}/inih/ini.c -o app

