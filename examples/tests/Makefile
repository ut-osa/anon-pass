## Camenisch and Lysyanskaya blind signature scheme.
V = @
CC = gcc
LD = gcc
INSTALL = cp
DESTDIR=$(VIRTUAL_ENV)
TEST = BENCH_REUP
DEBUG = 0
BENCHMARK = 0
CACHE = 0
EXT =
CFLAGS  = -g -I include -fPIC -O2
CFLAGS += -DDEBUG=$(DEBUG) -DBENCHMARK=$(BENCHMARK) -DCACHE=$(CACHE)
CFLAGS += -D$(TEST)
LDFLAGS =

## Basic and extra libraries
LIBS = -lgmp -lpbc -lpolarssl -lanonpass

## Compiled binaries
PROGS = cl_sig$(EXT) client_test$(EXT) fork$(EXT) opt_test$(EXT) \
	bench$(EXT) ec_group_test$(EXT) pbc_multibase$(EXT)
HEADERS = $(wildcard include/anon-pass/*.h)

OBJS = anon-pass.o client.o server.o

all: $(PROGS)
fork$(EXT): fork.o
client_test$(EXT): client_test.o client.o anon-pass.o
cl_sig$(EXT): cl_sig.o server.o client.o anon-pass.o
opt_test$(EXT): opt_test.o server.o client.o opt.o anon-pass.o
bench$(EXT): bench.o anon-pass.o
ec_group_test$(EXT): ec_group_test.o
pbc_multibase$(EXT): pbc_multibase.o
openssl-test$(EXT): LIBS=-lcrypto
openssl-test$(EXT): openssl-test.o

$(PROGS):
	$(V)echo [LD] $^ $@ && \
	$(LD) $^ $(LDFLAGS) $(LIBS) $($(@)_LIBS) -o $@

%.o: %.c
	$(V)echo [CC] $^ $@ && \
	$(CC) $< $(CFLAGS) -c -o $@

.PHONY: clean all
clean:
	rm -f *.o
	rm -f $(PROGS)
