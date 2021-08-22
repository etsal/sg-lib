cmake_minimum_required(VERSION 3.20) 
project(libsgd)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)
set(LIB_NAME sgd)

set(INC_DIR
  ./
)

set(SRCS
  sgd_message.c
  sgd_frame.c
  sgd_request.c
)

add_library(${LIB_NAME} STATIC ${SRCS})
#set_target_properties(${LIB_NAME} PROPERTIES COMPILE_FLAGS)

target_include_directories(${LIB_NAME} PUBLIC ${INC_DIR})



