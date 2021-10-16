CC := gcc48
BEARSSL_ROOT ?= ./deps/BearSSL

CFiles := $(wildcard app/*.c)

INCLUDE_PATHS := -Iapp/ -Iapp/include/ -I$(BEARSSL_ROOT)/inc 
CFLAGS := -std=c99 -g $(INCLUDE_PATHS)
LFLAGS := -lcuse -L$(BEARSSL_ROOT)/build -l:libbearssl.a \

OBJS := $(CFiles:.c=.o)

TARGET := app_u2f

.PHONY: all 

all: $(TARGET)
	
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC	<= $<"

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LFLAGS)
	@echo "LINK	<= $@"

.PHONY: clean

clean:
	rm -f app_u2f $(OBJS)
