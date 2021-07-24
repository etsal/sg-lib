cmake_minimum_required(VERSION 3.10)
project(nss_sg)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)

file(GLOB SRCS nss_sg.c src/*.c)  

add_compile_options(-fPIC -fno-stack-protector)

add_library(nss_sg SHARED ${SRCS})

set_property(TARGET nss_sg PROPERTY C_STANDARD 99)
set_property(TARGET nss_sg PROPERTY PREFIX "")

target_include_directories(nss_sg PUBLIC ./src)

add_custom_target(
  InstallPamModule ALL
  COMMAND sudo cp nss_sg.so /usr/lib/nss_sg.so.1
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/build
  COMMENT "Installing nss_sg.so to /usr/lib"
)

add_dependencies(InstallPamModule nss_sg)
