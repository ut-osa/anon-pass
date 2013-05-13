#ifndef _AGENT_UTIL_H
#define _AGENT_UTIL_H

#include <polarssl/ctr_drbg.h>
#include <polarssl/entropy.h>
#include <polarssl/ssl.h>

#include <anon-pass/anon-pass.h>
#include <anon-pass/client.h>
#include <anon-pass/debug.h>

#define MAX_ADDRS 8
#define DEFAULT_AUTH_PORT {8080,0}
#define DEFAULT_AUTH_URI_BASE "/pass"
#define DEFAULT_APP_PORT {9000,0}
#define DEFAULT_APP_URI_BASE "/auth"
#define DEFAULT_TIMEOUT 60
#define DEFAULT_PARAMS "param/a.param"
#define DEFAULT_CONF "anon-pass.conf"
#define DEFAULT_BENCH_CONF "anon-pass.bench.conf"
#define HTTP_VERSION "HTTP/1.1\r\n"
#define BUFFER_SZ 4096
#define HASH_DECODE_LEN 20

#define ANON_ERROR -1
#define ANON_AUTH_ERROR -2
#define ANON_TIME_ERROR -3

#define quit(msg) do {                          \
      errorf("%s: " msg, strerror(errno));      \
      rc = -1;                                  \
      goto out;                                 \
   } while (0)
#define quitf(msg, ...) do {                    \
      errorf(msg, __VA_ARGS__);                 \
      rc = -1;                                  \
      goto out;                                 \
   } while (0)
#define quit_loc(loc, msg) do {                 \
      errorf("%s: " msg, strerror(errno));      \
      rc = -1;                                  \
      goto out_##loc;                           \
   } while (0)
#define base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define base64_decoded_length(len)  (((len + 3) / 4) * 3)
#define KEY_BUFFER_LEN 128
#define COOKIE_BUFFER_LEN 512
#define CNX_UNSET  -1
#define CNX_NORMAL  0
#define CNX_SSL     1

struct addr_conf {
   int status;
   int num;
   int port[MAX_ADDRS];
   char *host[MAX_ADDRS];
};

struct connection {
   entropy_context  entropy;
   ctr_drbg_context ctr_drbg;
   ssl_session      ssn;
   ssl_context      ssl;
   int sockfd;
   struct addr_conf addr;
};

struct client_ctx {
   long epoch;
   int  len;
   int  key_len;
   int  auth_mode;
   char cookies[COOKIE_BUFFER_LEN];
   char key[KEY_BUFFER_LEN];
#if (BENCHMARK)
   char *login_str;
   size_t login_sz;
   char *reup_str;
   size_t reup_sz;
#endif
};

enum {PAIR, KEY, SIG, PUB, BENCH, AUTH, APP, MAX_CONF};
enum {PAIR_BIT  = 1<<PAIR,
      KEY_BIT  = 1<<KEY,
      SIG_BIT  = 1<<SIG,
      BENCH_BIT = 1<<BENCH,
      PUB_BIT   = 1<<PUB,
      AUTH_BIT  = 1<<AUTH,
      APP_BIT   = 1<<APP,
};

void connection_free(struct connection *cnx);
void destroy_client(struct client_ctx *ctx);
int client_connection_setup(struct addr_conf *addr, struct connection *cnx);
int client_connect(struct connection *cnx);
int client_params(struct connection *cnx, struct public_params *public_params, FILE *pubf);
int client_register(struct connection *cnx, struct public_params *public_params,
                    struct client_secret *client_secret, struct register_sig *sig);
int client_login(struct connection *cnx, struct public_params *public_params,
                 struct client_secret *client_secret, struct register_sig *sig,
                 struct client_ctx *ctx);
int client_reup(struct connection *cnx, struct public_params *public_params,
                struct client_secret *client_secret, struct client_ctx *ctx);
int client_app_update(struct connection *cnx, struct client_ctx *ctx);

static int client_send(struct connection *cnx, const char *type, const char *req, const uint8_t *data, size_t sz);
static int client_recv(struct connection *cnx, uint8_t **ret, size_t *ret_sz, struct client_ctx *ctx);

int decode_base64(uint8_t *dst, uint8_t *src, size_t src_sz);
int encode_base64(uint8_t *dst, uint8_t *src, size_t src_sz);

void callout_buffer(uint8_t *buffer, size_t sz);

#endif
