CC := gcc48

#/net/charm/usr/home/smdukova/sg/trusted/libpolicy/test

TINY_REGEX_C := ../../../deps/tiny-regex-c

CFiles := $(wildcard *.c) $(wildcard ../*.c) $(TINY_REGEX_C)/re.c ../../../common/sg_common.c

INCLUDE_PATHS := -I../ \
    -I../../../include \
    -I../../../deps \
    -I../../../deps/protobuf-c \
    -I../../../deps/tiny-regex-c \
    -I../../../common \
    -I/opt/intel/sgxsdk/include 

CFLAGS := -D__APP__ -std=c99 #$(shell pkg-config --cflags 'libprotobuf-c >= 1.0.0')
CFLAGS += $(INCLUDE_PATHS)

LFLAGS := #$(shell pkg-config --libs 'libprotobuf-c >= 1.0.0')
LFLAGS += -pthread -Ldeps/protobuf-c/build -l:libprotobuf-c.a

OBJS := $(CFiles:.c=.o)

TARGET := app

.PHONY: all app

all: $(TARGET)
	
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC	<= $<"

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LFLAGS)
	@echo "LINK	<= $@"

.PHONY: clean

clean:
	rm -f app *.o $(OBJS)

