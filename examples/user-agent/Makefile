## Camenisch and Lysyanskaya blind signature scheme.
V = @
CC = gcc
LD = gcc
APP_UPDATE := 1
BENCHMARK := 0
DEBUG := 0
LOGIN_MODE := 0
INSTALL := cp
DESTDIR := .
CFLAGS  = -g -fPIC
CFLAGS += -DDEBUG=$(DEBUG) -DBENCHMARK=$(BENCHMARK) -DLOGIN_ONLY_MODE=$(LOGIN_MODE)
LDFLAGS =

## Basic and extra libraries
LIBS = -lanonpass -lgmp -lpbc -lpolarssl

## Compiled binaries
PROGS = user-agent multi-user-agent multi-reg

all: $(PROGS)
debug: DEBUG = 1
debug: clean all
benchmark: APP_UPDATE=0
benchmark: BENCHMARK=1
benchmark: clean all
login_mode: LOGIN_MODE=1
login_mode: clean all
install: $(PROGS)
	$(V)mkdir -p $(DESTDIR)/bin
	$(V)for prog in $(PROGS); do 				\
		$(INSTALL) $$prog $(DESTDIR)/bin/$$prog;	\
	done

user-agent: user-agent.o agent-util.o
multi-user-agent: multi-user-agent.o agent-util.o
multi-reg: multi-reg.o agent-util.o
$(PROGS):
	$(V)echo [LD] $^ $@ && \
	$(LD) $^ $(LDFLAGS) $(LIBS) -o $@

%.o: %.c
	$(V)echo [CC] $^ $@ && \
	$(CC) $< $(CFLAGS) -c -o $@

.PHONY: clean all debug benchmark
clean:
	rm -rf *.o $(PROGS)
