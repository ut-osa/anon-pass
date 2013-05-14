## Hash Server Interface
V = @
CC = gcc
LD = gcc
INSTALL = cp
DESTDIR = /usr/local

.PHONY: all clean install

CFLAGS += -fPIC -Iinclude

LIB := libhs
SONAME := $(LIB).so
MAJOR := 1
MINOR := 1
STATIC := $(LIB).a
SHARED := $(SONAME).$(MAJOR).$(MINOR)
LIBHS := $(STATIC) $(SHARED)
TARGETS := $(SONAME).$(MAJOR) $(SONAME)
HEADERS = $(wildcard include/*.h)

OBJS := libhs.o

all: $(LIBHS)
install: $(LIBHS) $(HEADERS)
	$(V)mkdir -p $(DESTDIR)/lib
	$(V)$(INSTALL) $(LIBHS) $(DESTDIR)/lib
	$(V)mkdir -p $(DESTDIR)/include
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
	rm -f $(LIBHS)
