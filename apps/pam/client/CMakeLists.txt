cmake_minimum_required(VERSION 3.10)
project(ipc_client)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)

file(GLOB SRCS *.c ../src/*.c)  

add_executable(ipc_client ${SRCS})

target_include_directories(ipc_client PUBLIC ../src)

set_property(TARGET ipc_client PROPERTY C_STANDARD 99)
