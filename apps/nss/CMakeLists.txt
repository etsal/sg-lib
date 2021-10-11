cmake_minimum_required(VERSION 3.20) 
project(nss_sg)

# LIBSGD
set(SGD_ROOT ../../lib/libsgd)
find_library(SGD_LIB sgd HINTS ${SGD_ROOT}/build)

set(INC_DIR
  ./
  ${SGD_ROOT}
)

add_library(nss_sg SHARED
  nss_sg.c
)


set_target_properties(nss_sg PROPERTIES PREFIX "")
set_target_properties(nss_sg PROPERTIES SUFFIX ".so.1")

set_property(TARGET nss_sg PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(nss_sg PUBLIC ${INC_DIR})
target_link_libraries(nss_sg ${SGD_LIB})

add_custom_target(rebuild_libsgd
COMMAND cmake .. && gmake
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/../../server/lib/libsgd/build
COMMENT "Re compiling libsgd...")

add_dependencies(nss_sg rebuild_libsgd)
