You can find the bash script `install_instructions.sh` in the `scripts` directory. Otherwise, you can follow each step below:

    git submodule init
    git submodule update

## Dependencies
### BearSSL
    cd deps/BearSSL && gmake CC="gcc48"
    cd ..

### Protobuf-c (old version 1.3.3)
    tar -xvf protobuf-c-1.3.3.tar.gz
    mv protobuf-c-1.3.3 protobuf-c
    patch -p1 < stef.patch  
    cd protobuf-c && mkdir build && cd build && cmake -D CMAKE_C_COMPILER=gcc48 ../build-cmake && gmake
    cd ../../..


### WolfSSL with SGX
    touch deps/wolfssl/wolfssl/options.h
    cp scripts/wolfssl/build_ratls.sh deps/wolfssl/IDE/LINUX-SGX/
    patch -p1 -d deps/wolfssl < scripts/wolfssl/wolfssl.patch 
    # When promted enter 'y'.
    cd deps/wolfssl/IDE/LINUX-SGX
    ./build_ratls.sh
    cd -
### Tiny Regex
    patch -p1 -d deps/tiny-regex-c < scripts/patch_tiny_regex_sgx.patch



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

