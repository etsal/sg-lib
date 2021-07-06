CC := gcc48

SG_DIR = /net/charm/usr/home/smdukova/sg-lib

CFiles := $(wildcard *.c) \
  $(SG_DIR)/trusted/db.c \
  $(SG_DIR)/trusted/sg_util.c \
  $(wildcard $(SG_DIR)/trusted/libstore/*.c) \
  $(SG_DIR)/common/sg_common.c

INCLUDE_PATHS := -I../ \
    -I$(SG_DIR)/include \
    -I$(SG_DIR)/deps \
    -I$(SG_DIR)/deps/protobuf-c \
    -I$(SG_DIR)/common \
    -I/opt/intel/sgxsdk/include 

CFLAGS := -D__APP__ -std=c99 #$(shell pkg-config --cflags 'libprotobuf-c >= 1.0.0')
CFLAGS += $(INCLUDE_PATHS)

LFLAGS := #$(shell pkg-config --libs 'libprotobuf-c >= 1.0.0')
LFLAGS += -pthread -L$(SG_DIR)/deps/protobuf-c/build -l:libprotobuf-c.a

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

