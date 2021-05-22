cmake_minimum_required(VERSION 3.10)

project(sgtrusted)

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_COMMON_FLAGS "-m64 -O0 -g")

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

add_library(${PROJECT_NAME} STATIC ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE})

