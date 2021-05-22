#
# Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
TOP_DIR     = .
TRUSTED_DIR = ./trusted
CC 			:= gcc48
SGX_SDK 	:= /opt/intel/sgxsdk
SGX_MODE 	:= HW
SGX_ARCH 	:= x64
SGX_DEBUG 	:= 1

AENAME  = sg
EDLFILE := $(TRUSTED_DIR)/$(AENAME).edl

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
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	ENCLAVE_CFLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
	ENCLAVE_CFLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif

WOLFSSL_ROOT    := deps/wolfssl
WOLFSSL_C_FLAGS := -DWOLFSSL_SGX -DUSER_TIME -DWOLFSSL_SGX_ATTESTATION \
                   -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT \
                   -DFP_MAX_BITS=8192 
INCLUDE_DIRS += -I. \
				-I$(SGX_SDK)/include \
				-I$(SGX_SDK)/include/tlibc \
				-I$(TRUSTED_DIR) \
				-I$(TRUSTED_DIR)/internal \
				-I$(TRUSTED_DIR)/libstore \
                -I$(TRUSTED_DIR)/librassl \
				-I$(TRUSTED_DIR)/libpolicy \
                -Icommon \
				-Ideps \
				-Ideps/protobuf-c \
				-I$(WOLFSSL_ROOT)/ \
				-I$(WOLFSSL_ROOT)/wolfcrypt/ \
                -Ideps/tiny-regex-c


EDGER8R    := $(SGX_SDK)/bin/$(SGX_ARCH)/sgx_edger8r

CFLAGS   := $(ENCLAVE_CFLAGS)
CFLAGS   += -D__ENCLAVE__ $(WOLFSSL_C_FLAGS)
CFLAGS   += -std=c99 
ASFLAGS  := $(CFLAGS)

COMMON_C_SRCS 	:= $(wildcard common/*.c)
C_SRCS 			:= $(wildcard $(TRUSTED_DIR)/*.c $(TRUSTED_DIR)/libstore/*.c $(TRUSTED_DIR)/librassl/*.c $(TRUSTED_DIR)/libpolicy/*.c) \
			 	   $(shell echo "$(COMMON_C_SRCS) " | sed -e "s/.c /_enc.c /g") \
                   $(wildcard deps/tiny-regex-c/*.c)

OBJS := $(C_SRCS:.c=.o)
OBJS := $(sort $(OBJS))

LIBNAME    := libtsg.a

.PHONY: all
all: $(LIBNAME)

$(AENAME)_t.h: $(EDLFILE) $(EDGER8R)
	@$(EDGER8R) --trusted --header-only --search-path $(TRUSTED_DIR) --search-path $(TRUSTED_DIR)/librassl \
	--search-path $(SGX_SDK)/include $<
	@echo "GEN  =>  $@"

$(LIBNAME): $(OBJS)
	@$(AR) rcs $@ $^
	@echo "ARCHIVE =>  $@"

$(OBJS): $(AENAME)_t.h	
#$(OBJS): %.o: %.c
#	$(CC)  $(CFLAGS)   $(INCLUDE_DIRS) -c $< -o $@
#	@echo "CC  <=  $<"

common/%_enc.o: common/%.c
	@$(CC)  $(CFLAGS)   $(INCLUDE_DIRS) -c $< -o $@
	@echo "CC  <=  $<"

%.o: %.c
	@$(CC)  $(CFLAGS)   $(INCLUDE_DIRS) -c $< -o $@
	@echo "CC  <=  $<"


.PHONY: clean
clean:
	$(RM) $(LIBNAME) $(OBJS) $(AENAME)_t.h
