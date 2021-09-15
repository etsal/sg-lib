cmake_minimum_required(VERSION 3.10)
project(pam_app)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)


add_executable(pam_app pam_app.c)
add_executable(passwd_sg passwd_sg.c conv.c)
#target_include_directories( PUBLIC ../common)

target_link_libraries(pam_app -lpam)
target_link_libraries(passwd_sg -lpam)

set_property(TARGET pam_app PROPERTY C_STANDARD 99)
set_property(TARGET passwd_sg PROPERTY C_STANDARD 99)

