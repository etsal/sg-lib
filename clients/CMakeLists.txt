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
add_executable(sgget sg_get.c)
add_executable(sgsave sg_save.c)
add_executable(sggetuserby sg_getuserby.c)
add_executable(sgauthuser sg_authuser.c util.c)
add_executable(sgputuser sg_putuser.c util.c)

target_include_directories(sgput PUBLIC ${INC_DIR})
target_link_libraries(sgput ${SGD_LIB})

target_include_directories(sgget PUBLIC ${INC_DIR})
target_link_libraries(sgget ${SGD_LIB})

target_include_directories(sgsave PUBLIC ${INC_DIR})
target_link_libraries(sgsave ${SGD_LIB})

target_include_directories(sggetuserby PUBLIC ${INC_DIR})
target_link_libraries(sggetuserby ${SGD_LIB})

target_include_directories(sgauthuser PUBLIC ${INC_DIR})
target_link_libraries(sgauthuser ${SGD_LIB})

target_include_directories(sgputuser PUBLIC ${INC_DIR})
target_link_libraries(sgputuser ${SGD_LIB})

add_custom_target(rebuild_libsgd
COMMAND cmake .. && gmake
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/../server/lib/libsgd/build
COMMENT "Re compiling libsgd...")

add_dependencies(sgput rebuild_libsgd)
add_dependencies(sgget rebuild_libsgd)
add_dependencies(sgsave rebuild_libsgd)
add_dependencies(sggetuserby rebuild_libsgd)
