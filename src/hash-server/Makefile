## Hash Server Interface
V = @
CC = gcc
LD = gcc
INSTALL = cp
DESTDIR = .

.PHONY: all clean install

BENCHMARK = 0

CFLAGS  += -I ../libhs/include $(shell pkg-config --cflags glib-2.0)
CFLAGS  += -DBENCHMARK=$(BENCHMARK)

LDFLAGS := $(shell pkg-config --libs glib-2.0) -pthread

PROGS := hash_server
SRC  := $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(SRC))

all: $(PROGS)
debug: CFLAGS+=-DDEBUG
debug: $(PROGS)
benchmark: BENCHMARK=1
benchmark: $(PROGS)
$(PROGS): $(OBJS)
	$(V)echo [LD] $^ $@ && $(LD) $^ -o $@ $(LDFLAGS)
install: $(PROGS)
	$(V)mkdir -p $(DESTDIR)/bin
	$(V)$(INSTALL) $(PROGS) $(DESTDIR)/bin

%.o: %.c
	$(V)echo [CC] $^ $@ && $(CC) $< $(CFLAGS) -c -o $@

clean:
	rm -f *.o
	rm -f $(PROGS)

hash_server: hash_server.o util.o hash.o
