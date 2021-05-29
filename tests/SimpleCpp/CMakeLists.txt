cmake_minimum_required(VERSION 3.10) 

project(SampleEnclave)

find_package(Threads REQUIRED) #pthread

set(CMAKE_C_COMPILER /usr/local/bin/clang)
set(CMAKE_CXX_COMPILER /usr/local/bin/clang++)

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_MODE "HW")
set(SGX_ARCH "x64")
set(SGX_DEBUG 1)

set(SGX_COMMON_CFLAGS "")


set(SG_LIBRARY_PATH "${CMAKE_SOURCE_DIR}/../../build")
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

### App Settings
set(App_Name "app")

if(SGX_MODE STREQUAL "HW")
    set(Urts_Library_Name "sgx_urts")
else()
    set(Urts_Library_Name "sgx_urts_sim")
endif()

file(GLOB App_Cpp_Files 
    App/*.cpp 
    App/sgx_utils/*.cpp
)

set(App_Include_Paths 
    ${SGX_SDK}/include
    App
)

#set(App_C_Flags "${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(App_C_Flags "${SGX_COMMON_CFLAGS}")

# Three configuration modes: debug, prerelease, release
if(SGX_DEBUG EQUAL 1)
    set(App_C_Flags "${App_C_Flags} -DDEBUG -UNDEBUG -UEDEBUG")
elseif(SGX_PRERELEASE EQUAL 1)
    set(App_C_Flags "${App_C_Flags} -DNDEBUG -DEDEBUG -UDEBUG")
else()
    set(App_C_Flags "${App_C_Flags} -DNDEBUG -UEDEBUG -UDEBUG")
endif()

set(App_Cpp_Flags "${App_C_Flags} -Wno-attributes -frtti")#-nostdinc++ ")
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

file(GLOB Enclave_Src
    Enclave/*.cpp 
    Enclave/Sealing/*.cpp
)

set(Enclave_Include_Paths
    Enclave
    ${SGX_SDK}/include 
    ${SGX_SDK}/include/tlibc 
    ${SGX_SDK}/include/libcxx
)

set(Enclave_C_Flags
"${SGX_COMMON_CFLAGS} \
-nostdinc \
-fvisibility=hidden \
-fpie \
-ffunction-sections -fdata-sections -fstack-protector \
-fstack-protector"
)

set(Enclave_Cpp_Flags "${Enclave_C_Flags} -std=c++03 -nostdinc++")

set(Enclave_Link_Flags
"-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
-Wl,--whole-archive -l${Trts_Library_Name} -Wl,--no-whole-archive \
-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l${Crypto_Library_Name} -l${Service_Library_Name} -Wl,--end-group \
-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
-Wl,--defsym,__ImageBase=0"
)


#set(Enclave_Libs
#    "${Trts_Library_Name}  sgx_tstdc sgx_tcxx ${Crypto_Library_Name} ${Service_Library_Name}"
#)

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


add_custom_target(SignEnclave ALL
    COMMAND ${SGX_ENCLAVE_SIGNER} sign -key ${ENCLAVE_DIR}/Enclave_private.pem -enclave lib${Enclave_Name}.so -out lib${Signed_Enclave_Name}.so -config ${Enclave_Config_File}
#    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "SIGN => lib${Signed_Enclave_Name}so" 
    OUTPUT lib${Signed_Enclave_Name}.so
    DEPENDS ${App_Name}
)

#link_directories(${SGX_LIBRARY_PATH} /usr/local/lib/gcc48)

# These are the targets (1) the app executable and (2) the shared enclave lib
add_executable(${App_Name} App/Enclave_u.c ${App_Cpp_Files})
3add_library(${Enclave_Name} SHARED Enclave/Enclave_t.c ${Enclave_Src})

target_include_directories(${App_Name} PUBLIC ${App_Include_Paths} )
#target_include_directories(${Enclave_Name} PUBLIC ${Enclave_Include_Paths})

target_link_directories(${App_Name} PRIVATE ${SG_LIBRARY_PATH} /usr/local/lib/gcc48)
#target_link_directories(${Enclave_Name} PUBLIC )

set_target_properties(${App_Name} PROPERTIES COMPILE_FLAGS ${App_Cpp_Flags})
set_target_properties(${App_Name} PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(${Enclave_Name} PROPERTIES COMPILE_FLAGS ${Enclave_Cpp_Flags})
set_target_properties(${Enclave_Name} PROPERTIES POSITION_INDEPENDENT_CODE OFF)

#target_compile_features(${App_Name} )

target_link_libraries(${App_Name} ${Urts_Library_Name} ${CMAKE_THREAD_LIBS_INIT} )#libsguntrusted.a)
target_link_libraries(${Enclave_Name} ${Enclave_Link_Flags})# ${SG_LIBRARY_PATH}/libsgtrusted.a)

# Run Edger8r before builds
add_dependencies(${App_Name} UntrustedEdger8r)
add_dependencies(${Enclave_Name} TrustedEdger8r)
add_dependencies(SignEnclave ${Enclave_Name})
