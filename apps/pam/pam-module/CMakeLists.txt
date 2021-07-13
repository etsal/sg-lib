cmake_minimum_required(VERSION 3.10)
project(pam_sg)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)

file(GLOB SRCS pam_sg.c ../src/*.c)  

add_compile_options(-fPIC -fno-stack-protector)

add_library(pam_sg SHARED ${SRCS})

set_property(TARGET pam_sg PROPERTY C_STANDARD 99)
set_property(TARGET pam_sg PROPERTY PREFIX "")

target_include_directories(pam_sg PUBLIC ../src)

add_custom_target(
  InstallPamModule ALL
  COMMAND sudo cp pam_sg.so /usr/lib/pam_sg.so
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/build
  COMMENT "Installing pam_sg.so to /usr/lib"
)

add_dependencies(InstallPamModule pam_sg)
