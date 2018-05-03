WRAPPER_DIR := ../../syscall_wrapper

CC := gcc
AR := ar

CFLAGS := -Wall -fPIC -I$(WRAPPER_DIR) -g
LDFLAGS := -lnvmed -lforestdb -shared

SHARED_LIB = libffs.so
STATIC_LIB = libffs.a

INSTALL_HEADERS = lib_ffs.h

OBJS = lib_ffs.o utils/radix-tree.o

default: $(SHARED_LIB) $(STATIC_LIB)

$(SHARED_LIB): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(STATIC_LIB): $(OBJS)
	$(AR) rcv $@ $^

install: $(SHARED_LIB)
	install -m 644 -o root -g root $(INSTALL_HEADERS) /usr/local/include/
	install -m 644 -o root -g root $(SHARED_LIB) /usr/local/lib
	ldconfig 

clean:
	rm -f $(ALL_PROGS) $(SHARED_LIB) $(STATIC_LIB) $(OBJS)

clobber: clean

.PHONY: default clean clobber
