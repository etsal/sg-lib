cmake_minimum_required(VERSION 3.10)
project(policy)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)
set(REGEX_DIR "${CMAKE_SOURCE_DIR}/../../../../../deps/tiny-regex-c")

file(GLOB SRCS main.c ${REGEX_DIR}/re.c)  

add_compile_options(-fPIC -fno-stack-protector)

add_executable(app ${SRCS})

#set_property(TARGET nss_sg PROPERTY C_STANDARD 99)
#set_property(TARGET nss_sg PROPERTY PREFIX "")

target_include_directories(app PUBLIC ${REGEX_DIR})

