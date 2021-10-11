CC = gcc48
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

WOLFSSL_ROOT    := /net/charm/usr/home/smdukova/sg/deps/wolfssl
SGX_WOLFSSL_LIB := $(WOLFSSL_ROOT)/IDE/LINUX-SGX
WOLFSSL_C_FLAGS := -DWOLFSSL_SGX -DUSER_TIME -DWOLFSSL_SGX_ATTESTATION \
                   -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT \
                   -DFP_MAX_BITS=8192 

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS = -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS = -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SUPPLIED_KEY_DERIVATION), 1)
        SGX_COMMON_CFLAGS += -DSUPPLIED_KEY_DERIVATION
endif


SGX_COMMON_CFLAGS += $(WOLFSSL_C_FLAGS)

######## Common Files Settings ##
Common_Link_Flags := -Ldeps/BearSSL/build -l:libbearssl.a \
					 -L$(SGX_WOLFSSL_LIB) -lwolfssl.sgx.static.lib

#$(shell pkg-config --libs 'libprotobuf-c >= 1.0.0')

######## App Settings ########
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_C_Files := $(wildcard app/*.c)

App_Include_Paths :=-I. \
					-I$(SGX_SDK)/include \
					-Iapp -Iapp/include \
					-Ideps  \
					-I/net/charm/usr/home/smdukova/sg/include\
					-I$(WOLFSSL_ROOT)/ \
					-I$(WOLFSSL_ROOT)/wolfcrypt/

# -std=c99 to allow 'for' loop initial declarations
App_C_Flags = -D__APP__ -fPIC -Wno-attributes -std=c99 $(SGX_COMMON_CFLAGS)  $(App_Include_Paths) 

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := -L$(SGX_LIBRARY_PATH) \
				  -l$(Urts_Library_Name) -lsgx_uae_service  -lsgx_ukey_exchange\
			 	  -lpthread \
				  -lcuse \
				  -lcurl \
				  -L/net/charm/usr/home/smdukova/sg -l:libusg.a \
				  $(Common_Link_Flags)

#ifneq ($(SGX_MODE), HW)
#	App_Link_Flags += -lsgx_uae_service_sim
#else
#	App_Link_Flags += -lsgx_uae_service
#endif

App_C_Objects := $(App_C_Files:.c=.o)
App_Name := u2f

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := $(wildcard enclave/*.c) $(wildcard enclave/x509/*.c)

Enclave_Include_Paths :=-I. \
						-I$(SGX_SDK)/include \
						-I$(SGX_SDK)/include/tlibc \
						-Ienclave -Ienclave/x509 \
						-Ideps \
						-Ideps/protobuf-c \
						-I/net/charm/usr/home/smdukova/sg/include\
						-I$(WOLFSSL_ROOT)/ \
						-I$(WOLFSSL_ROOT)/wolfcrypt/

Enclave_C_Flags = -D__ENCLAVE__ -DDEBUG

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags += $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
	Enclave_C_Flags += $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif
#-nostdinc

Enclave_C_Flags += $(Enclave_Include_Paths) -std=c99 -fno-builtin-fwrite

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Ldeps/protobuf-c/build -l:libprotobuf-c.a \
	-L../sg -l:libtsg.a \
	$(Common_Link_Flags) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=enclave/enclave.lds 

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := enclave/enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name) $(Enclave_Name)
	echo "The project has been built in release hardware mode."
	echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	echo "To sign the enclave use the command:"
	echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	echo "You can also sign the enclave using an external signing tool."
	echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	echo "The project has been built in pre-release simulation mode."
else
	echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	$(CURDIR)/$(App_Name) 	
	echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@echo "TODO: REMOVE ME!!"
	@echo $(Common_C_Files)
	rm -f .config_* $(App_Name) $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) app/enclave_u.* $(Enclave_C_Objects) enclave/enclave_t.* 
	touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########

app/enclave_u.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd app && $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl \
		--search-path ../enclave --search-path $(SGX_SDK)/include --search-path ../../sg/include
	@echo "GEN  =>  $@"

app/enclave_u.o: app/enclave_u.c
	$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

app/%.o: app/%.c	
	@$(CC) $(SGX_COMMON_CFLAGS)  $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

common/%_app.o: common/%.c
	@$(CC) $(SGX_COMMON_CFLAGS)  $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(App_Name): app/enclave_u.o $(App_C_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"
	
######## Enclave Objects ########

enclave/enclave_t.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/enclave.edl \
		--search-path ../enclave --search-path $(SGX_SDK)/include --search-path ../../sg/include
	@echo "GEN  =>  $@"

enclave/enclave_t.o: enclave/enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.c	
	@$(CC) $(SGX_COMMON_CFLAGS)  $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

common/%_enc.o: common/%.c	
	@$(CC) $(SGX_COMMON_CFLAGS)  $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"


$(Enclave_Name): enclave/enclave_t.o $(Enclave_C_Objects)
	$(CC) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	rm -f .config_* $(App_Name) $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) app/enclave_u.* $(Enclave_C_Objects) enclave/enclave_t.*

