cmake_minimum_required(VERSION 3.10)
project(ipc_client)
set(CMAKE_C_COMPILER /usr/local/bin/gcc48)
file(GLOB SRCS *.c ../../server/App/ipc_util.c)  
add_executable(ipc_client ${SRCS})
target_include_directories(ipc_client PUBLIC ../../server/App)

