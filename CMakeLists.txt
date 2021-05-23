cmake_minimum_required(VERSION 3.10)

project(sgtrusted)

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
set(SGX_COMMON_FLAGS "-m64 -O0 -g")
set(TRUSTED_DIR "${CMAKE_SOURCE_DIR}/trusted")
set(EDLFILE "${CMAKE_SOURCE_DIR}/trusted/sg.edl")

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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ENCLAVE_C_FLAGS} ${WOLFSSL_C_FLAGS}")

file (GLOB SOURCES 
    trusted/*.c 
    trusted/libstore/*.c 
    trusted/librassl/*.c
    common/*.c
)

set (INCLUDE
    ${SGX_SDK}/include 
    ${SGX_SDK}/include/tlibc
    include
    deps
    deps/protobuf-c
    deps/wolfssl
)

#add_custom_command(
#    OUTPUT sg_t.h
#    COMMAND "${EDGER8R}" --trusted --header-only --search-path "${TRUSTED_DIR}" --search-path "${TRUSTED_DIR}/librassl" --search-path "${SGX_SDK}/include" sg_t.h
#    DEPENDS sg_t.h
#    COMMENT "Generated trusted edge routines"
#)

add_custom_target(
    Edger8rHeader
    COMMAND ${SGX_EDGER8R} --trusted --header-only --search-path ${TRUSTED_DIR} --search-path ${TRUSTED_DIR}/librassl --search-path ${SGX_SDK}/include ${EDLFILE}
    COMMAND cp sg_t.h ${CMAKE_SOURCE_DIR}/include
    COMMENT "Generating trusted proxy and bridge"
)

#add_custom_target(
#sgedge
#COMMAND "${EDGER8R}" --trusted --header-only --search-path "${TRUSTED_DIR}" --search-path "${TRUSTED_DIR}/librassl" --search-path "${SGX_SDK}/include" sg_t.h
#)



include_directories(${INCLUDE})
add_library(${PROJECT_NAME} STATIC ${SOURCES})

add_dependencies(${PROJECT_NAME} Edger8rHeader)


