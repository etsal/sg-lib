cmake_minimum_required(VERSION 3.10)
project(policy)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)

set(DEPS_DIR "${CMAKE_SOURCE_DIR}/../../../../deps")
set(REGEX_DIR "${DEPS_DIR}/tiny-regex-c")
set(SG_DIR "${CMAKE_SOURCE_DIR}/../../include")

file(GLOB SRCS *.c ${REGEX_DIR}/re.c)  
set(INCLUDE ${DEPS_DIR} ${REGEX_DIR} ${SG_DIR})

add_library(policy STATIC ${SRCS})

add_compile_options(-fPIC -fno-stack-protector)

target_include_directories(policy PUBLIC ${INCLUDE})

