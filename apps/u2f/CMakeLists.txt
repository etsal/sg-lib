cmake_minimum_required(VERSION 3.10) 

project(u2f-key)

find_package(Threads REQUIRED) #pthread

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)
set(CMAKE_CXX_COMPILER /usr/local/bin/g++48)

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_MODE "HW")
set(SGX_ARCH "x64")
set(SGX_DEBUG 1)

set(DEPS_DIR "${CMAKE_SOURCE_DIR}/../../deps")
set(LIBSG_ROOT "${CMAKE_SOURCE_DIR}/../../lib/libsg")

#LIBCUSE

# WOLFSSL
set(WOLFSSL_ROOT "${DEPS_DIR}/wolfssl")
set(WOLFSSL_C_FLAGS "-DWOLFSSL_SGX -DUSER_TIME -DWOLFSSL_SGX_ATTESTATION \
-DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192")
find_library(WOLFSSL_LIB wolfssl.sgx.static.lib HINTS ${WOLFSSL_ROOT}/IDE/LINUX-SGX)

# BEARSSL
set(BEARSSL_ROOT "${DEPS_DIR}/BearSSL")
find_library(BEARSSL_LIB bearssl HINTS ${BEARSSL_ROOT}/build)

# PROTOBUF C
set(PROTOBUF_ROOT "${DEPS_DIR}/protobuf-c")
find_library(PROTOBUF_LIB protobuf-c HINTS ${PROTOBUF_ROOT}/build)

# Libsgd
#set(SGD_LIB_ROOT "${CMAKE_SOURCE_DIR}/lib/libsgd")
#find_library(SGD_LIB sgd HINTS ${CMAKE_SOURCE_DIR}/lib/libsgd/build)

set(ENCLAVE_DIR "${CMAKE_SOURCE_DIR}/Enclave")
set(APP_DIR "${CMAKE_SOURCE_DIR}/App")

if("${SGX_ARCH}" STREQUAL "x86")
    set(SGX_COMMON_CFLAGS "-m32")
    set(SGX_LIBRARY_PATH "${SGX_SDK}/lib")
    set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x86/sgx_sign")
    set(SGX_EDGER8R "${SGX_SDK}/bin/x86/sgx_edger8r")
else()
    set(SGX_COMMON_CFLAGS "-m64")
    set(SGX_LIBRARY_PATH "${SGX_SDK}/lib64")
    set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x64/sgx_sign")
    set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
endif()

if("${SGX_DEBUG}" STREQUAL "1")
    set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O0 -g")
else()
    set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2")
endif()

set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS}")

### App Settings
set(App_Name "app")

if(SGX_MODE STREQUAL "HW")
    set(Urts_Library_Name "sgx_urts")
else()
    set(Urts_Library_Name "sgx_urts_sim")
endif()

file(GLOB App_C_Files 
    App/*.c
)

set(App_Include_Paths
    .
    App
    App/include
    ${SGX_SDK}/include
    ${LIBSG_ROOT}/include
    ${DEPS_DIR}
    ${DEPS_DIR}/protobuf-c 
    ${WOLFSSL_ROOT}
    ${WOLFSSL_ROOT}/wolfcrypt/
)

set(App_C_Flags "${SGX_COMMON_CFLAGS}")

# Three configuration modes: debug, prerelease, release
if(SGX_DEBUG EQUAL 1)
    set(App_C_Flags "${App_C_Flags} -DDEBUG -UNDEBUG -UEDEBUG")
elseif(SGX_PRERELEASE EQUAL 1)
    set(App_C_Flags "${App_C_Flags} -DNDEBUG -DEDEBUG -UDEBUG")
else()
    set(App_C_Flags "${App_C_Flags} -DNDEBUG -UEDEBUG -UDEBUG")
endif()

set(App_C_Flags "${App_C_Flags} -D__APP__ -Wno-attributes -std=c99")#-nostdinc++ ")

### Enclave Settings
set(Enclave_Name "enclave")
set(Signed_Enclave_Name "enclave.signed")
set(Enclave_Config_File "${ENCLAVE_DIR}/Enclave.config.xml")

if(SGX_MODE STREQUAL "HW")
    set(Trts_Library_Name "sgx_trts")
    set(Service_Library_Name "sgx_tservice")
else()
    set(Trts_Library_Name "sgx_trts_sim")
    set(Service_Library_Name "sgx_tservice_sim")
endif()

set(Crypto_Library_Name "sgx_tcrypto")

file(GLOB Enclave_C_Files
    Enclave/*.c 
    Enclave/x509/*.c
)

set(Enclave_Include_Paths
    .
    Enclave
    Enclave/x509
    App/include
    ${LIBSG_ROOT}/include
    ${DEPS_DIR}
    ${SGX_SDK}/include 
    ${SGX_SDK}/include/tlibc 
    ${SGX_SDK}/include/libcxx
    ${WOLFSSL_ROOT}
    ${WOLFSSL_ROOT}/wolfcrypt
    ${PROTOBUF_ROOT}
)


set(Enclave_C_Flags
#    ${SGX_COMMON_CFLAGS}
    -m64 -O0 -g
#${WOLFSSL_C_FLAGS}
    -nostdinc
    -fvisibility=hidden
    -fpie
    -ffunction-sections 
    -fdata-sections 
    -fstack-protector
    -fstack-protector
    -std=c99
)


set(Enclave_C_Flags "${Enclave_C_Flags}") #-std=c++03 -nostdinc++")

set(Enclave_Link_Flags
"-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
-L${LIBSG_ROOT}/build -l:libsgtrusted.a \
-L${PROTOBUF_ROOT}/build -l:libprotobuf-c.a \
-L${BEARSSL_ROOT}/build -l:libbearssl.a \
-L${WOLFSSL_ROOT}/IDE/LINUX-SGX -l:libwolfssl.sgx.static.lib.a \
-Wl,--whole-archive -l${Trts_Library_Name} -Wl,--no-whole-archive \
-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l${Crypto_Library_Name} -l${Service_Library_Name} -Wl,--end-group \
-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
-Wl,--defsym,__ImageBase=0"
)

### Start
add_custom_target(UntrustedEdger8r
COMMAND ${SGX_EDGER8R} --untrusted ${ENCLAVE_DIR}/Enclave.edl --search-path ${ENCLAVE_DIR}
  --search-path ${LIBSG_ROOT}/include
  --search-path ${SGX_SDK}/include
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/App
COMMENT "GEN => Enclave_u.h"
)

add_custom_target(TrustedEdger8r
COMMAND  ${SGX_EDGER8R} --trusted ${ENCLAVE_DIR}/Enclave.edl --search-path ${ENCLAVE_DIR} --search-path ${LIBSG_ROOT}/include --search-path ${SGX_SDK}/include
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/Enclave
COMMENT "GEN => Enclave_t.h"
)

add_custom_target(SignEnclave ALL
COMMAND ${SGX_ENCLAVE_SIGNER} sign -key ${ENCLAVE_DIR}/Enclave_private.pem -enclave lib${Enclave_Name}.so -out lib${Signed_Enclave_Name}.so -config ${Enclave_Config_File}
#    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
COMMENT "SIGN => lib${Signed_Enclave_Name}so" 
OUTPUT lib${Signed_Enclave_Name}.so
DEPENDS ${App_Name}
)

add_custom_target(CopyConfig ALL
  COMMAND cp config.ini ${CMAKE_SOURCE_DIR}/build
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  #COMMENT "COPY config.ini to /build"
)

add_custom_target(FinalMessage ALL
   COMMAND echo "Done\n"
   COMMENT "SUCCESSFULLY BUILT ${App_Name}"
)

#link_directories(${SGX_LIBRARY_PATH} /usr/local/lib/gcc48)

# These are the targets (1) the app executable and (2) the shared enclave lib
add_executable(${App_Name} App/Enclave_u.c ${App_C_Files})
add_library(${Enclave_Name} SHARED Enclave/Enclave_t.c ${Enclave_C_Files})

target_include_directories(${Enclave_Name} PUBLIC ${Enclave_Include_Paths})

set_target_properties(${App_Name} PROPERTIES COMPILE_FLAGS "${App_C_Flags} ${WOLFSSL_C_FLAGS}")
set_target_properties(${App_Name} PROPERTIES POSITION_INDEPENDENT_CODE ON)

#set_target_properties(${Enclave_Name} PROPERTIES COMPILE_FLAGS "${Enclave_C_Flags}")
target_compile_options(${Enclave_Name} PUBLIC ${Enclave_C_Flags})
set_target_properties(${Enclave_Name} PROPERTIES POSITION_INDEPENDENT_CODE OFF)


target_include_directories(${App_Name} PUBLIC ${App_Include_Paths})

target_link_directories(${App_Name} PRIVATE 
${SGX_LIBRARY_PATH}
${LIBSG_ROOT}/build 
#/usr/local/lib/gcc48
#${BEARSSL_ROOT}/build
#${WOLFSSL_ROOT}/IDE/LINUX-SGX
#${PROTOBUF_ROOT}/build
)

target_link_libraries(${App_Name} 
${Urts_Library_Name}    #.so 
sgx_uae_service         #.so
curl                    #.so
cuse                    #.so
${CMAKE_THREAD_LIBS_INIT} #pthread
libsgx_ukey_exchange.a 
libsguntrusted.a
#libprotobuf-c.a
#libbearssl.a
#libwolfssl.sgx.static.lib.a
${PROTOBUF_LIB}
${BEARSSL_LIB}
${WOLFSSL_LIB}
)

target_link_directories(${Enclave_Name} PUBLIC 
${SGX_LIBRARY_PATH} 
${LIBSG_ROOT}/build 
#${LIBSG_ROOT}/deps/protobuf-c/build )
)

target_link_libraries(${Enclave_Name}
${Enclave_Link_Flags}
#${Trts_Library_Name}
#sgx_tstdc
#sgx_tcxx
#sgx_tkey_exchange
#${Crypto_Library_Name}
#${Service_Library_Name}
#libsgtrusted.a
#-L${LIBSG_ROOT}/build -l:libprotobuf-c.a
#-L${BEARSSL_ROOT}/build -l:libbearssl.a
#-L${WOLFSSL_ROOT}/IDE/LINUX-SGX -lwolfssl.sgx.static.lib
)

# Run Edger8r before builds
add_dependencies(${App_Name} UntrustedEdger8r TrustedEdger8r)
add_dependencies(${Enclave_Name} ${App_Name}) #TrustedEdger8r)
add_dependencies(SignEnclave ${Enclave_Name})
add_dependencies(CopyConfig SignEnclave)
add_dependencies(FinalMessage CopyConfig)
