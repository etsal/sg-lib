cmake_minimum_required(VERSION 3.20) 
project(pam_sg)

# LIBSGD
set(SGD_ROOT ../../../lib/libsgd)
find_library(SGD_LIB sgd HINTS ${SGD_ROOT}/build)

set(INC_DIR
  ./
  ${SGD_ROOT}
)

add_library(pam_sg SHARED
  pam_sg.c
)


set_target_properties(pam_sg PROPERTIES PREFIX "")
#set_target_properties(pam_sg PROPERTIES SUFFIX ".so.1")

set_property(TARGET pam_sg PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(pam_sg PUBLIC ${INC_DIR})
target_link_libraries(pam_sg ${SGD_LIB})

add_custom_target(rebuild_libsgd
COMMAND cmake .. && gmake
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/../../../server/lib/libsgd/build
COMMENT "Re compiling libsgd...")

add_custom_target(
  InstallPamModule ALL
  COMMAND sudo cp pam_sg.so /usr/lib/
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/build
  COMMENT "Installing pam_sg.so to /usr/lib"
)

add_dependencies(pam_sg rebuild_libsgd)
add_dependencies(InstallPamModule pam_sg)
