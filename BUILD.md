You can find the bash script `install_instructions.sh` in the `scripts` directory. Otherwise, you can follow each step below:

## Dependencies
### BearSSL
    cd <BASEDIR>/deps/BearSSL; CC=gcc48 gmake 

### Protobuf-c (old version 1.3.3) 
### [CAREFUL: CMake defaults to g++ if g++11 is installed, causing C++ compilation errors]
    cd <BASEDIR>/deps/protobuf-c; mkdir build; cd build;
    cmake -D CMAKE_C_COMPILER=gcc48 CMAKE_CXX_COMPILER="clang++" ../build-cmake; gmake

### WolfSSL with SGX
    cd <BASEDIR>/deps/wolfssl/IDE/LINUX-SGX; ./build_ratls.sh

## Code
### Before starting
- Build assumes that `sgxsdk` and `sgxpsw` is installed in `/opt/intel/sgxXXX`
- Make sure the kernel module is loaded and aesm service is running, that is

        sudo kldload sgx
        cd /opt/intel/sgxpsw/aesm && sudo ./aesm_service 
### Building the library (libsgtrusted.a & libsgtrusted.a)
    cd lib/libsg
    cd build && cmake .. && gmake

### Building the server application (linked against ^^)
    cd server
    cd build && cmake .. && gmake
    sudo ./app

