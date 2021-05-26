cmake_minimum_required(VERSION 3.10) 

project(SampleEnclave)

find_package(Threads REQUIRED) #pthread

set(CMAKE_C_COMPILER /usr/local/bin/gcc48)
set(CMAKE_CXX_COMPILER /usr/local/bin/g++48)

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_MODE "HW")
set(SGX_ARCH "x64")
set(SGX_DEBUG 1)

set(ENCLAVE_DIR "${CMAKE_SOURCE_DIR}/Enclave")
set(APP_DIR "${CMAKE_SOURCE_DIR}/App")

if("${SGX_ARCH}" STREQUAL "x86")
    set(SGX_COMMON_CFLAGS "-m32")
    set(SGX_LIBRARY_PATH "${SGX_SDK}/lib")
    set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x86/sgx_sign")
    set(SGX_EDGER8R "${SGX_SDK}/bin/x86/sgx_edger8r")
else()
    set(SGX_COMMON_CFLAGS "-m64")
    set(SGX_LIBRARY_PATH "${SGX_SDK}/lib")
    set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x64/sgx_sign")
    set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
endif()

if("${SGX_DEBUG}" STREQUAL "1")
    set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O0 -g")
else()
    set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2")
endif()

### App Settings
set(App_Name "app")

if(SGX_MODE STREQUAL "HW")
    set(Urts_Library_Name "sgx_urts")
else()
    set(Urts_Library_Name "sgx_urts_sim")
endif()

file(GLOB App_Cpp_Files 
    App/*.cpp 
    App/Edger8rSyntax/*.cpp
    App/TrustedLibrary/*.cpp
)

set(App_Include_Paths 
    ${SGX_SDK}/include
    Include
    App
)

set(App_C_Flags "${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")

# Three configuration modes: debug, prerelease, release
if(SGX_DEBUG EQUAL 1)
    set(App_C_Flags "${App_C_Flags} -DDEBUG -UNDEBUG -UEDEBUG")
elseif(SGX_PRERELEASE EQUAL 1)
    set(App_C_Flags "${App_C_Flags} -DNDEBUG -DEDEBUG -UDEBUG")
else()
    set(App_C_Flags "${App_C_Flags} -DNDEBUG -UEDEBUG -UDEBUG")
endif()

set(App_Cpp_Flags "${App_C_Flags} -std=c++11")
#set(App_Link_Flags "${SGX_COMMON_CFLAGS} -L${SGX_LIBRARY_PATH} -l${Urts_Library_Name} -lpthread")
set(App_Link_Libs "${Urts_Library_Name} pthread")

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

file(GLOB Enclave_Cpp_Files
    Enclave/*.cpp 
    Enclave/Edger8rSyntax/*.cpp
    Enclave/TrustedLibrary/*.cpp
)

set(Enclave_Include_Paths
    Include
    Enclave
    ${SGX_SDK}/include 
    ${SGX_SDK}/include/tlibc 
    ${SGX_SDK}/include/libcxx
)

set(Enclave_C_Flags
    ${SGX_COMMON_CFLAGS} 
    -nostdinc 
    -fvisibility=hidden 
    -fpie 
    -fstack-protector 
)

set(Enclave_Cpp_Flags "${Enclave_C_Flags} -std=c++03 -nostdinc++")

set(Enclave_Link_Flags
    "${SGX_COMMON_CFLAGS} -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
    -Wl,--whole-archive -l${Trts_Library_Name} -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l${Crypto_Library_Name} -l${Service_Library_Name} -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
    -Wl,--defsym,__ImageBase=0"
)

### Start
add_custom_target(UntrustedEdger8r
    COMMAND ${SGX_EDGER8R} --untrusted ${ENCLAVE_DIR}/Enclave.edl --search-path ${ENCLAVE_DIR} --search-path ${SGX_SDK}/include
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/App
    COMMENT "GEN => Enclave_u.h"
)

add_custom_target(TrustedEdger8r
    COMMAND  ${SGX_EDGER8R} --trusted ${ENCLAVE_DIR}/Enclave.edl --search-path ${ENCLAVE_DIR} --search-path ${SGX_SDK}/include
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/Enclave
    COMMENT "GEN => Enclave_t.h"
)

add_custom_target(SignEnclave
    COMMAND ${SGX_ENCLAVE_SIGNER} sign -key ${ENCLAVE_DIR}/Enclave_private.pem -enclave lib${Enclave_Name}.so -out lib${Signed_Enclave_Name}.so -config ${Enclave_Config_File}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "SIGN => libenclave.signed.so" 
)

link_directories(${SGX_LIBRARY_PATH})

#add_executable(${App_Name} ${APP_DIR}/Enclave_u.c ${App_Cpp_Files})
add_library(${Enclave_Name} SHARED "${Enclave_Cpp_Files}")

#target_include_directories(${App_Name} PUBLIC ${App_Include_Paths})
target_include_directories(${Enclave_Name} PUBLIC ${Enclave_Include_Paths})

#set_target_properties(${App_Name} PROPERTIES COMPILE_FLAGS ${App_Cpp_Flags})
set_target_properties(${Enclave_Name} PROPERTIES COMPILE_FLAGS ${Enclave_Cpp_Flags})

#target_link_libraries(${App_Name} INTERFACE ${App_Link_Flags} )
#target_link_libraries(${Enclave_Name} INTERFACE ${Enclave_Link_Flags})

#target_link_libraries(${App_Name} ${Urts_Library_Name} ${CMAKE_THREAD_LIBS_INIT})

# Run Edger8r before builds
#add_dependencies(${App_Name} UntrustedEdger8r)
add_dependencies(${Enclave_Name} TrustedEdger8r)



