cmake_minimum_required(VERSION 3.10)
project(pam_app)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)

file(GLOB SRCS *.c)  

add_executable(pam_app ${SRCS})

#target_include_directories( PUBLIC ../common)

target_link_libraries(pam_app -lpam)

set_property(TARGET pam_app PROPERTY C_STANDARD 99)
