cmake_minimum_required(VERSION 3.10)

project(policy)

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)
set(CMAKE_CXX_COMPILER /usr/local/bin/g++48)
set(SGX_COMMON_FLAGS "-m64 -O0 -g -std=c99")
set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
set(EDLFILE "${CMAKE_SOURCE_DIR}/trusted/sg.edl")
set(DEPS_DIR "${CMAKE_SOURCE_DIR}/../../deps")
set(TRUSTED_DIR "${CMAKE_SOURCE_DIR}/trusted")
set(TRUSTED_LIB "${PROJECT_NAME}trusted")
set(UNTRUSTED_LIB "${PROJECT_NAME}untrusted")

set(ENCLAVE_C_FLAGS "${SGX_COMMON_FLAGS} \
-nostdinc \
-fvisibility=hidden \
-fpie \
-ffunction-sections \
-fdata-sections \
-fstack-protector")

set(WOLFSSL_C_FLAGS "-DWOLFSSL_SGX -DUSER_TIME \
-DWOLFSSL_SGX_ATTESTATION \
-DWOLFSSL_KEY_GEN  \
-DWOLFSSL_CERT_GEN \
-DWOLFSSL_CERT_EXT \
-DFP_MAX_BITS=8192")

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ENCLAVE_C_FLAGS} ${WOLFSSL_C_FLAGS} -D__ENCLAVE__")

set(EDL_SRCS
  trusted/policy.edl
)

file (GLOB TRUSTED_SRCS 
    trusted/*.c 
    ${DEPS_DIR}/tiny-regex-c/re.c
)

file (GLOB UNTRUSTED_SRCS
    untrusted/*.c
)

set (TRUSTED_INCLUDE
    ${SGX_SDK}/include 
    ${SGX_SDK}/include/tlibc
    include
    ${DEPS_DIR}
)

set (UNTRUSTED_INCLUDE
    ${SGX_SDK}/include
    include
    ${DEPS_DIR}
)

# Copy all header files (trusted and untrusted) to include
add_custom_target(
    CopyHeaders
    COMMAND cp trusted/*.h include
    COMMAND cp untrusted/*.h include
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Copying header files to include"
)

# Generate trusted bridge functions before compiling trusted library (add_dependencies)
add_custom_target(
    TrustedEdger8r
    COMMAND ${SGX_EDGER8R} --trusted --header-only --search-path ${TRUSTED_DIR} --search-path ${SGX_SDK}/include ${EDLFILE}
    COMMAND cp sgwp_t.h ${CMAKE_SOURCE_DIR}/include
    COMMENT "Generating trusted proxy and bridge"
)

add_custom_target(
    UntrustedEdger8r
    COMMAND ${SGX_EDGER8R} --untrusted --header-only --search-path ${TRUSTED_DIR} --search-path ${SGX_SDK}/include ${EDLFILE}
    COMMAND cp sgwp_u.h ${CMAKE_SOURCE_DIR}/include
    COMMENT "Generating untrusted proxy and bridge"
)

#include_directories(${INCLUDE})

add_library(${TRUSTED_LIB} STATIC ${TRUSTED_SRCS})
add_library(${UNTRUSTED_LIB} STATIC ${UNTRUSTED_SRCS})

set_target_properties(${TRUSTED_LIB} PROPERTIES COMPILE_FLAGS "${ENCLAVE_C_FLAGS} -D__ENCLAVE__")
set_target_properties(${UNTRUSTED_LIB} PROPERTIES COMPILE_FLAGS "-std=c99 -fPIC -Wno-attributes -D__APP__")

target_include_directories(${TRUSTED_LIB} PUBLIC ${TRUSTED_INCLUDE})
target_include_directories(${UNTRUSTED_LIB} PUBLIC ${UNTRUSTED_INCLUDE})

add_dependencies(${UNTRUSTED_LIB}  CopyHeaders UntrustedEdger8r)
add_dependencies(${TRUSTED_LIB} CopyHeaders TrustedEdger8r)

