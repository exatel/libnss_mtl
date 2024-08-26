VERSION ?= 0.0.1

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
DEP := $(SRC:.c=.d)
TEST_BIN := mtl_test

CC := gcc
LD := gcc
RM := rm

CFLAGS := -O2 -fPIC -shared -std=c11
CPPFLAGS := -Wall -Wextra -Werror -MD -D_XOPEN_SOURCE=600 -D_GNU_SOURCE
LDFLAGS = $(CFLAGS)

DESTDIR :=
prefix := /usr

libdir := $(prefix)/lib

get_target_lib = libnss_mtl.so.$1

.PHONY: all clean install test

all: libnss_mtl.so.$(VERSION)

test: $(TEST_BIN)

clean:
	$(RM) -f $(call get_target_lib,$(VERSION)) $(OBJ) $(TEST_BIN) $(TEST_BIN).o

install:
	echo "not yet available"

$(call get_target_lib,$(VERSION)): $(OBJ)
	$(LD) $(LDFLAGS) -Wl,-soname,$(call get_target_lib,2) -o $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TEST_BIN): CFLAGS := -O1 -std=c11 -g
$(TEST_BIN): $(TEST_BIN).o $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $^

-include $(DEP)