cmake_minimum_required(VERSION 3.20) 
project(sg_cli)

# LIBSGD
set(SGD_ROOT ../server/lib/libsgd)
find_library(SGD_LIB sgd HINTS ${SGD_ROOT}/build)

set(INC_DIR
  ./
  ${SGD_ROOT}
)

add_executable(sgput sg_put.c)

target_include_directories(sgput PUBLIC ${INC_DIR})
target_link_libraries(sgput ${SGD_LIB})


add_custom_target(rebuild_libsgd
COMMAND cmake .. && gmake
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/../server/lib/libsgd/build
COMMENT "Re compiling libsgd...")

add_dependencies(sgput rebuild_libsgd)
