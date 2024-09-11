VERSION ?= 1.0.2

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
DEP := $(SRC:.c=.d)
TEST_BIN := mtl_test
CONF := nss_mtl.conf

CC := gcc
LD := gcc
RM := rm
INSTALL := install
SYMLINK := ln -s

CFLAGS := -O2 -fPIC -shared -std=c11
CPPFLAGS := -Wall -Wextra -Werror -MD -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -DNDEBUG -isystem $(SYSROOT)/usr/include
LDFLAGS = $(CFLAGS)

DESTDIR :=
prefix := /usr

libdir := $(prefix)/lib
sysconfdir := /etc

get_target_lib = libnss_mtl.so.$1

.PHONY: all clean install test

all: libnss_mtl.so.$(VERSION)

test: $(TEST_BIN)

clean:
	$(RM) -f $(call get_target_lib,$(VERSION)) $(OBJ) $(DEP) $(TEST_BIN) $(TEST_BIN).o $(TEST_BIN).d

install: $(call get_target_lib,$(VERSION)) $(CONF)
	$(INSTALL) -D -m 755 $< $(DESTDIR)$(libdir)/$<
	$(SYMLINK) $< $(DESTDIR)$(libdir)/$(call get_target_lib,2)
	$(INSTALL) -D -m 644 $(CONF) $(DESTDIR)$(sysconfdir)/$(notdir $(CONF))


$(call get_target_lib,$(VERSION)): $(OBJ)
	$(LD) $(LDFLAGS) -Wl,-soname,$(call get_target_lib,2) -o $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TEST_BIN): CFLAGS := -O1 -std=c11 -g
$(TEST_BIN): CPPFLAGS += -DNSS_MTL_CONFIG_FILE="\"$(CURDIR)/nss_mtl.conf\""
$(TEST_BIN): $(TEST_BIN).o $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $^

-include $(DEP)