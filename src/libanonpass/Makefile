## Camenisch and Lysyanskaya blind signature scheme.
V = @
CC = gcc
LD = gcc
INSTALL = cp
DESTDIR = /usr/local

.PHONY: all clean install debug benchmark

BENCHMARK = 0
CACHE = 0
DEBUG = 0

CFLAGS += -I include -fPIC -O2
CFLAGS += -DDEBUG=$(DEBUG) -DBENCHMARK=$(BENCHMARK) -DCACHE=$(CACHE)

LIB := libanonpass
SONAME := $(LIB).so
MAJOR := 0
MINOR := 1
STATIC := $(LIB).a
SHARED := $(SONAME).$(MAJOR).$(MINOR)
LIBANONPASS := $(STATIC) $(SHARED)
TARGETS := $(SONAME).$(MAJOR) $(SONAME)
HEADERS = $(wildcard include/anon-pass/*.h)

OBJS := anon-pass.o client.o server.o

LIBS := -lgmp -lpbc -lpolarssl

all: $(LIBANONPASS)
debug: DEBUG = 1
debug: clean all libs
benchmark: BENCHMARK = 1
benchmark: clean all libs
install: $(LIBANONPASS) $(HEADERS)
	$(V)mkdir -p $(DESTDIR)/lib
	$(V)$(INSTALL) $(LIBANONPASS) $(DESTDIR)/lib
	$(V)mkdir -p $(DESTDIR)/include/anon-pass
	$(V)for header in $(HEADERS); do 			\
		$(INSTALL) $$header $(DESTDIR)/$$header;	\
	done || true
	$(V)cd $(DESTDIR)/lib/ &&				\
	for target in $(TARGETS); do				\
		ln -f -s $(SHARED) $$target;			\
	done

$(SHARED): $(OBJS)
	$(V)echo [LD] $^ $@ && $(LD) -shared -Wl,-soname,$(SHARED) -o $@ $(OBJS)

$(STATIC): $(OBJS)
	$(V)echo [AR] $@ && $(AR) r $@ $(OBJS)
	$(V)echo [RL] $@ && $(AR) s $@
	$(V)echo [RANLIB] $@ && ranlib $@

%.o: %.c
	$(V)echo [CC] $^ $@ && $(CC) $< $(CFLAGS) -c -o $@

clean:
	rm -f *.o
	rm -f $(LIBANONPASS)
