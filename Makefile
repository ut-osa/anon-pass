### Makefile to help build Anon-Pass

V=@

SRC_PATH=$(PWD)/src

TARGETS = nginx hash-server client

all: $(TARGETS)
nginx: build-nginx
hash-server: build-hash-server
client: build-client

## Configuring and building nginx
NGINX_PATH=$(SRC_PATH)/nginx

init-nginx: $(NGINX_PATH)/.stamp-init
$(NGINX_PATH)/.stamp-init:
	$(V)echo [init] nginx &&				\
	git submodule update --init $(NGINX_PATH) &&		\
	(patch -p2 -d $(NGINX_PATH) < $(SRC_PATH)/nginx.diff || true) &&	\
	touch $(NGINX_PATH)/.stamp-init

configure-nginx: $(NGINX_PATH)/.stamp-config
$(NGINX_PATH)/.stamp-config: $(NGINX_PATH)/.stamp-init
	$(V)echo [conf] nginx &&				\
	cd $(NGINX_PATH) &&					\
	./configure --add-module=../anon-pass-module --with-http_ssl_module &&	\
	touch $(NGINX_PATH)/.stamp-config

build-nginx: $(NGINX_PATH)/.stamp-build
$(NGINX_PATH)/.stamp-build: $(NGINX_PATH)/.stamp-config
	$(V)echo [build] nginx &&				\
	$(MAKE) -C $(NGINX_PATH) && touch $(NGINX_PATH)/.stamp-build

clean-nginx:
	$(MAKE) -C $(NGINX_PATH) clean
	rm -f $(NGINX_PATH)/.stamp-*

## Configuring and build other components
HASH_SERVER_PATH=$(SRC_PATH)/hash-server

build-hash-server: $(HASH_SERVER_PATH)/.stamp-build
$(HASH_SERVER_PATH)/.stamp-build:
	$(V)echo [build] hash-server &&				\
	$(MAKE) -C $(HASH_SERVER_PATH) && touch $(HASH_SERVER_PATH)/.stamp-build

clean-hash-server:
	$(MAKE) -C $(HASH_SERVER_PATH) clean
	rm -f $(HASH_SERVER_PATH)/.stamp-*

## Build client
CLIENT_PATH=$(PWD)/examples/user-agent
build-client: $(CLIENT_PATH)/.stamp-build
$(CLIENT_PATH)/.stamp-build:
	$(V)echo [build] client &&				\
	$(MAKE) -C $(CLIENT_PATH) && touch $(CLIENT_PATH)/.stamp-build

clean-client:
	$(MAKE) -C $(CLIENT_PATH) clean
	rm -f $(CLIENT_PATH)/.stamp-*

## Clean

realclean: clean-nginx clean-hash-server
