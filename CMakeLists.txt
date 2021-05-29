cmake_minimum_required(VERSION 3.10)

project(sg)

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
set(SGX_COMMON_FLAGS "-m64 -O0 -g")
set(TRUSTED_DIR "${CMAKE_SOURCE_DIR}/trusted")
set(EDLFILE "${CMAKE_SOURCE_DIR}/trusted/sg.edl")

set(TRUSTED_LIB "${PROJECT_NAME}trusted")
set(UNTRUSTED_LIB "${PROJECT_NAME}untrusted")

set(ENCLAVE_C_FLAGS "${SGX_COMMON_FLAGS} \
-nostdinc \
-fvisibility=hidden \
-fpie \
-ffunction-sections \
-fdata-sections -fstack-protector")

set(WOLFSSL_C_FLAGS "-DWOLFSSL_SGX -DUSER_TIME \
-DWOLFSSL_SGX_ATTESTATION \
-DWOLFSSL_KEY_GEN  \
-DWOLFSSL_CERT_GEN \
-DWOLFSSL_CERT_EXT \
-DFP_MAX_BITS=8192")

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ENCLAVE_C_FLAGS} ${WOLFSSL_C_FLAGS} -D__ENCLAVE__")

file (GLOB TRUSTED_SRCS 
    trusted/*.c 
    trusted/libstore/*.c 
    trusted/librassl/*.c
    common/*.c
)

file (GLOB UNTRUSTED_SRCS
    untrusted/*.c
    untrusted/librassl/*.c
    common/*.c
)

set (TRUSTED_INCLUDE
    ${SGX_SDK}/include 
    ${SGX_SDK}/include/tlibc
    include
    deps
    deps/protobuf-c
    deps/wolfssl
)

set (UNTRUSTED_INCLUDE
    ${SGX_SDK}/include
    include
    deps
    deps/protobuf-c
    deps/wolfssl
    /usr/local/include
)

# Copy all header files (trusted and untrusted) to include
# This can probably be done with a scipt
add_custom_target(
    CopyHeaders
    COMMAND cp trusted/*.h include
    COMMAND cp trusted/*.edl include
    COMMAND cp trusted/libstore/*.h include
    COMMAND cp trusted/librassl/*.h include
    COMMAND cp trusted/librassl/*.edl include
    COMMAND cp untrusted/*.h include
    COMMAND cp common/*.h include
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Copying header files to ./include"
)

# Generate trusted bridge functions before compiling trusted library (add_dependencies)
add_custom_target(
    TrustedEdger8r
    COMMAND ${SGX_EDGER8R} --trusted --header-only --search-path ${TRUSTED_DIR} --search-path ${TRUSTED_DIR}/librassl --search-path ${SGX_SDK}/include ${EDLFILE}
    COMMAND cp sg_t.h ${CMAKE_SOURCE_DIR}/include
    COMMENT "Generating trusted proxy and bridge"
)

add_custom_target(
    UntrustedEdger8r
    COMMAND ${SGX_EDGER8R} --untrusted --header-only --search-path ${TRUSTED_DIR} --search-path ${TRUSTED_DIR}/librassl --search-path ${SGX_SDK}/include ${EDLFILE}
    COMMAND cp sg_u.h ${CMAKE_SOURCE_DIR}/include
    COMMENT "Generating untrusted proxy and bridge"
)

#include_directories(${INCLUDE})

add_library(${TRUSTED_LIB} STATIC ${TRUSTED_SRCS})
add_library(${UNTRUSTED_LIB} STATIC ${UNTRUSTED_SRCS})

set_target_properties(${TRUSTED_LIB} PROPERTIES COMPILE_FLAGS "${ENCLAVE_C_FLAGS} ${WOLFSSL_C_FLAGS} -D__ENCLAVE__")
set_target_properties(${UNTRUSTED_LIB} PROPERTIES COMPILE_FLAGS "-I/usr/include ${WOLFSSL_C_FLAGS} -fPIC -Wno-attributes -D__APP__")

target_include_directories(${TRUSTED_LIB} PRIVATE ${TRUSTED_INCLUDE})
target_include_directories(${UNTRUSTED_LIB} PRIVATE ${UNTRUSTED_INCLUDE})

#add_dependencies(${UNTRUSTED_LIB}  CopyHeaders UntrustedEdger8r)
add_dependencies(${TRUSTED_LIB} CopyHeaders TrustedEdger8r)

