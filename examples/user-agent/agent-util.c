#include "agent-util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/error.h>

static void ssl_debug(void *ctx, int leve, const char *str)
{
   fprintf((FILE *)ctx, "%s", str);
   fflush((FILE *)ctx);
}

static int set_nonblock(struct connection *cnx)
{
   int fl;
   if (cnx->addr.status == CNX_NORMAL) {
      fl = fcntl(cnx->sockfd, F_GETFL);
      fcntl(cnx->sockfd, F_SETFL, fl | O_NONBLOCK);
   }
   return 0;
}

int client_connection_setup(struct addr_conf *addr, struct connection *cnx)
{
   cnx->addr = *addr;
   cnx->sockfd = -1;
   return 1;
}

/**
 * @in:  (const char *host) Server IP address, (int port) Server port
 * @out: (none)
 * @ret: socket fd
 */
int client_connect(struct connection *cnx)
{
   int rc = 0, sockfd, entry;
   struct linger linger = {1, 0};

   if (cnx->sockfd >= 0 || cnx->addr.num == 0) {
      goto out;
   }
   entry = rand() % cnx->addr.num;
   if (cnx->addr.status == CNX_SSL) {
      memset(&cnx->ssn, 0, sizeof(ssl_session));
      memset(&cnx->ssl, 0, sizeof(ssl_context));

      entropy_init(&cnx->entropy);
      if ((rc = ctr_drbg_init(&cnx->ctr_drbg, entropy_func, &cnx->entropy,
                              "blah", strlen("blah"))) != 0)
         quitf("Failed to initialize ctr_drbg - %d", rc);

      if ((rc = net_connect(&cnx->sockfd, cnx->addr.host[entry], cnx->addr.port[entry])) != 0)
         quitf("Failed to connect to %s:%d - %d", cnx->addr.host[entry], cnx->addr.port[entry], rc);

      if ((rc = ssl_init(&cnx->ssl)) != 0)
         quitf("Failed to initialize ssl - %d", rc);

      ssl_set_endpoint(&cnx->ssl, SSL_IS_CLIENT);
      ssl_set_authmode(&cnx->ssl, SSL_VERIFY_NONE);

      ssl_set_rng(&cnx->ssl, ctr_drbg_random, &cnx->ctr_drbg);
      ssl_set_dbg(&cnx->ssl, ssl_debug, stderr);
      ssl_set_bio(&cnx->ssl, net_recv, &cnx->sockfd, net_send, &cnx->sockfd);

      ssl_set_ciphersuites(&cnx->ssl, ssl_default_ciphersuites);
      ssl_set_session(&cnx->ssl, 1, 600, &cnx->ssn);
      if ((rc = setsockopt(cnx->sockfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) < 0)
         quit("Could not set sockopt");
   } else if (cnx->addr.status == CNX_NORMAL) {
      struct sockaddr_in addr;
      if ((rc = socket(AF_INET, SOCK_STREAM, 0)) < 0)
         quit("Could not create socket");
      sockfd = rc;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons(cnx->addr.port[entry]);
      if ((rc = inet_pton(AF_INET, cnx->addr.host[entry], &addr.sin_addr)) <= 0)
         quit("Could not translate addr");

      if ((rc = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr))) < 0)
         quit("Could not connect to server");
      cnx->sockfd = sockfd;
      if ((rc = setsockopt(cnx->sockfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) < 0)
         quit("Could not set sockopt");
      set_nonblock(cnx);
   }

 out:
   return rc;
}

void connection_free(struct connection *cnx)
{
   if (cnx->addr.status == CNX_SSL && cnx->sockfd >= 0) {
      ssl_close_notify(&cnx->ssl);
      net_close(cnx->sockfd);
      ssl_free(&cnx->ssl);
      memset(&cnx->ssl, 0, sizeof(cnx->ssl));
   } else if (cnx->addr.status == CNX_NORMAL && cnx->sockfd >= 0) {
      close(cnx->sockfd);
   }
   cnx->sockfd = -1;
}

void destroy_client(struct client_ctx *ctx)
{
#if (BENCHMARK)
   if (ctx->login_str) {
      free(ctx->login_str);
   }
   if (ctx->reup_str) {
      free(ctx->reup_str);
   }
#endif
}

/**
 * @in:  (int sockfd) Connected socket
 * @out: (struct public_params *) Initialized public parameters
 * @ret: success or failure
 */
int client_params(struct connection *cnx, struct public_params *public_params, FILE *pubf)
{
   int rc;
   uint8_t *buffer = NULL;
   size_t sz = 0;
   off_t off = 0;

   if ((rc = client_send(cnx, "GET", DEFAULT_AUTH_URI_BASE"/params", NULL, 0)) < 0)
      quit("Could not send params request");

   if ((rc = client_recv(cnx, &buffer, &sz, NULL)) < 0)
      quit("Could not read params");

   /* Unwrap Data */
   pub_init(public_params, NULL);
   decode_base64(buffer, buffer, rc);
   off += element_from_bytes(public_params->g, buffer + off);
   off += element_from_bytes(public_params->X, buffer + off);
   off += element_from_bytes(public_params->Y, buffer + off);
   off += element_from_bytes(public_params->Z, buffer + off);
   off += element_from_bytes(public_params->W, buffer + off);
   pub_pp_init(public_params);

   if (!client_verify_pub(public_params))
      quit("Invalid server public key!");

   if (pubf) {
      element_out_str(pubf, ELE_BASE, public_params->g);
      fprintf(pubf, "\n");
      element_out_str(pubf, ELE_BASE, public_params->X);
      fprintf(pubf, "\n");
      element_out_str(pubf, ELE_BASE, public_params->Y);
      fprintf(pubf, "\n");
      element_out_str(pubf, ELE_BASE, public_params->Z);
      fprintf(pubf, "\n");
   }
 out:
   if (buffer)
      free(buffer);
   return rc;
}

int client_register(struct connection *cnx, struct public_params *public_params,
                    struct client_secret *client_secret, struct register_sig *sig)
{
   int rc = 0;
   uint8_t *tmp = NULL, *buffer = NULL;
   size_t sz = 0;
   off_t off = 0;
   struct register_msg msg;

   if (!client_create_reg_msg(public_params, client_secret, &msg))
      quit("Could not create register message");
   tmp = malloc(RAW_REG_MSG_LEN);
   memset(tmp, 0, RAW_REG_MSG_LEN);

   off += element_to_bytes(tmp + off, msg.M);
   off += element_to_bytes(tmp + off, msg.R);
   off += element_to_bytes(tmp + off, msg.rg);
   off += element_to_bytes(tmp + off, msg.rZ);

   if (off > RAW_REG_MSG_LEN)
      quit_loc(reg, "Whoops...heap overflow >_<");

   sz = sizeof("Cookie: data=;\r\n") - 1;
   sz += base64_encoded_length(off);
   buffer = malloc(sz);
   memset(buffer, 0, sz);

   sz = sizeof("Cookie: data=") - 1;
   memcpy(buffer, "Cookie: data=", sz);
   sz += encode_base64(buffer + sz, tmp, off);
   buffer[sz++] = ';';
   buffer[sz++] = '\r';
   buffer[sz++] = '\n';

   if ((rc = client_send(cnx, "GET", DEFAULT_AUTH_URI_BASE"/register", buffer, sz)) < 0)
      quit_loc(reg, "Could not send register message");

   if ((rc = client_recv(cnx, &buffer, &sz, NULL)) < 0)
      quit_loc(reg, "Register recv failed");

   if (rc == 0)
      quit_loc(reg, "Registration rejected");

   /* Unwrap Data */
   reg_sig_init(public_params, sig);
   rc = decode_base64(buffer, buffer, rc);
   off = 0;
   off += element_from_bytes(sig->A,  buffer + off);
   off += element_from_bytes(sig->B,  buffer + off);
   off += element_from_bytes(sig->ZB, buffer + off);
   off += element_from_bytes(sig->C,  buffer + off);

   if ((rc = client_verify_reg_sig(public_params, client_secret, sig)) == 0) {
      reg_sig_clear(sig, 0);
      quit_loc(reg, "Server signature did not verify");
   }

   rc = 0;
 out_reg:
   reg_msg_clear(&msg);
 out:
   if (tmp)
      free(tmp);
   if (buffer)
      free(buffer);
   return rc;
}

int client_login(struct connection *cnx, struct public_params *public_params,
                 struct client_secret *client_secret, struct register_sig *sig,
                 struct client_ctx *ctx)
{
   int rc = 0, count = 0;
   uint8_t *buffer = NULL, *tmp = NULL;
   size_t sz = 0;
   off_t off = 0;
   struct login_msg msg;

 retry:
   if (count++ >= 5) {
      /* Just give up... */
      quit("Too many retries");
   }
   debugf("%s: try %d", count);
#if (BENCHMARK)
   if (ctx->login_str) {
      if ((rc = client_send(cnx, "GET", DEFAULT_AUTH_URI_BASE"/login",
                            ctx->login_str, ctx->login_sz)) < 0)
         quit("Could not send login message");
      if ((rc = client_recv(cnx, &buffer, &sz, ctx)) < 0)
         quit("Login recv failed");
      goto out;
   }
#endif
   if (!(ctx->epoch = client_create_login_msg(public_params, client_secret, sig, &msg, ctx->epoch)))
      quit("Could not create login message");

   if (!tmp)
      tmp = malloc(RAW_LOGIN_LEN);
   memset(tmp, 0, RAW_LOGIN_LEN);

   off += element_to_bytes(tmp + off, msg.A);
   off += element_to_bytes(tmp + off, msg.B);
   off += element_to_bytes(tmp + off, msg.ZB);
   off += element_to_bytes(tmp + off, msg.C);

   off += element_to_bytes(tmp + off, msg.d);
   off += element_to_bytes(tmp + off, msg.r);
   off += element_to_bytes(tmp + off, msg.r2);

   off += element_to_bytes(tmp + off, msg.R1);
   off += element_to_bytes(tmp + off, msg.Yt);
   off += element_to_bytes(tmp + off, msg.R2);
   off += element_to_bytes(tmp + off, msg.t);

   if (off > RAW_LOGIN_LEN)
      quit_loc(msg, "Whoops...heap overflow >_<");

   sz = sizeof("Cookie: data=;\r\n") - 1;
   sz += base64_encoded_length(off);
   if (!buffer)
      buffer = malloc(sz);
   memset(buffer, 0, sz);

   sz = sizeof("Cookie: data=") - 1;
   memcpy(buffer, "Cookie: data=", sz);
   sz += encode_base64(buffer + sz, tmp, off);
   buffer[sz++] = ';';
   buffer[sz++] = '\r';
   buffer[sz++] = '\n';

#if (BENCHMARK)
   if (!ctx->login_str) {
      ctx->login_sz = sz;
      ctx->login_str = malloc(sz);
      memcpy(ctx->login_str, buffer, sz);
   }
#endif

   if ((rc = client_send(cnx, "GET", DEFAULT_AUTH_URI_BASE"/login", buffer, sz)) < 0)
      quit_loc(msg, "Could not send login message");

   if ((rc = client_recv(cnx, &buffer, &sz, ctx)) < 0) {
      quit_loc(msg, "Login recv failed");
   }

   if (rc == 0)
      quit_loc(msg, "Login rejected");

   /* Error checking! */
   if (strncmp(buffer, "fail", 4) == 0) {
      /* Find the new offset... */
      long offset = 0;
      if (strncmp(buffer + 5, "(access)", 8) == 0) {
         debug("Failed: double login attempt");
         rc = ANON_AUTH_ERROR;
         goto out;
      }
      offset = strtol(strstr(buffer, ":") + 2, NULL, 10) - time(NULL);
      debugf("Failed: setting offset to %ld", offset);
      set_offset(offset);
      rc = -1;
      sz = 0;
      off = 0;
      login_msg_clear(&msg);
      rc = ANON_TIME_ERROR;
      goto retry;
   }

   /* Remake the token */
   off = element_to_bytes(buffer, msg.t);
   hash_element(buffer + off, msg.Yt);
   off += HASH_DECODE_LEN;

   if (ctx->auth_mode && strlen(ctx->key) != 0) {
      memcpy(ctx->cookies + ctx->len, " tok=", 5);
      ctx->len += 5;
      ctx->len += encode_base64(ctx->cookies + ctx->len, buffer, off);
      ctx->cookies[ctx->len++] = ';';
   } else {
      memcpy(ctx->key, " key=", (ctx->key_len = 5));
      ctx->key_len += encode_base64(ctx->key + ctx->key_len, buffer, off);
      ctx->key[ctx->key_len++] = ';';
   }

 out_msg:
   login_msg_clear(&msg);
 out:
   if (tmp)
      free(tmp);
   if (buffer)
      free(buffer);

   return rc;
}

int client_reup(struct connection *cnx, struct public_params *public_params,
                struct client_secret *client_secret, struct client_ctx *ctx)
{
   int rc = 0;
   uint8_t *buffer = NULL, *tmp = NULL;
   size_t sz = 0;
   off_t off = 0;
   long next_epoch = 0;
   struct reup_msg msg;

#if (BENCHMARK)
   if (ctx->reup_str) {
      if ((rc = client_send(cnx, "GET", DEFAULT_AUTH_URI_BASE"/reup",
                            ctx->reup_str, ctx->reup_sz)) < 0)
         quit("Could not send reup message");
      if ((rc = client_recv(cnx, &buffer, &sz, ctx)) < 0)
         quit("Reup recv failed");
      goto out;
   }
#endif

   if (!(next_epoch = client_create_reup_msg(public_params, client_secret, &msg, ctx->epoch)))
      quit("Could not create reup message");

   tmp = malloc(RAW_REUP_LEN);
   memset(tmp, 0, RAW_REUP_LEN);

   off += element_to_bytes(tmp + off, msg.Yt);
   off += element_to_bytes(tmp + off, msg.Rt);
   off += element_to_bytes(tmp + off, msg.Ys);
   off += element_to_bytes(tmp + off, msg.Rs);
   off += element_to_bytes(tmp + off, msg.a);
   off += element_to_bytes(tmp + off, msg.t);

   if (off > RAW_REUP_LEN)
      quit_loc(msg, "Whoops...heap overflow >_<");

   sz = sizeof("Cookie: data=;\r\n") - 1;
   sz += base64_encoded_length(off);
   buffer = malloc(sz);
   memset(buffer, 0, sz);

   sz = sizeof("Cookie: data=") - 1;
   memcpy(buffer, "Cookie: data=", sz);
   sz += encode_base64(buffer + sz, tmp, off);
   buffer[sz++] = ';';
   buffer[sz++] = '\r';
   buffer[sz++] = '\n';

#if (BENCHMARK)
   if (!ctx->reup_str) {
      ctx->reup_sz = sz;
      ctx->reup_str = malloc(sz);
      memcpy(ctx->reup_str, buffer, sz);
   }
#endif

   if ((rc = client_send(cnx, "GET", DEFAULT_AUTH_URI_BASE"/reup", buffer, sz)) < 0)
      quit_loc(msg, "Could not send reup message");
   else if (rc == 0)
      quit_loc(msg, "Could not connect");

   if ((rc = client_recv(cnx, &buffer, &sz, ctx)) < 0)
      quit_loc(msg, "Reup recv failed");
   else if (rc == 0)
      quit_loc(msg, "Recieved 0 data");

   if (rc == 0) {
      error("No data returned");
      quit_loc(msg, "Reup rejected");
   }

   /* Remake the next token */
   element_add_ui(msg.t, msg.t, 1);
   off = element_to_bytes(buffer, msg.t);
   hash_element(buffer + off, msg.Ys);
   off += HASH_DECODE_LEN;

   memcpy(ctx->cookies + ctx->len, " tok=", 5);
   ctx->len += 5;
   ctx->len += encode_base64(ctx->cookies + ctx->len, buffer, off);
   ctx->cookies[ctx->len++] = ';';

   ctx->epoch ++;
   if (ctx->epoch != next_epoch) {
      error("Epochs don't match for the next round...");
   }
 out_msg:
   reup_msg_clear(&msg);
 out:
   if (tmp)
      free(tmp);
   if (buffer)
      free(buffer);

   return rc;
}

int client_app_update(struct connection *cnx, struct client_ctx *ctx)
{
   int rc = 0;
   uint8_t *ret = NULL;
   size_t sz;

   if (cnx->addr.status == CNX_UNSET) {
      /* not connected */
      goto out;
   }
   ret = malloc(COOKIE_BUFFER_LEN);

   /* Send */
   memset(ret, 0, COOKIE_BUFFER_LEN);
   sz = sizeof("Cookie:") - 1;
   memcpy(ret, "Cookie:", sz);
   memcpy(ret + sz, ctx->key, ctx->key_len);
   sz += ctx->key_len;
   memcpy(ret + sz, ctx->cookies, ctx->len);
   sz += ctx->len;
   ret[sz++] = '\r'; ret[sz++] = '\n';

   if ((rc = client_send(cnx, "HEAD", DEFAULT_APP_URI_BASE, (char *)ret, sz)) < 0)
      quit("App update send failed");

   /* Only recv a header */
   if ((rc = client_recv(cnx, &ret, &sz, NULL)) < 0)
      quit("App update recv failed");

 out:
   if (ret)
      free(ret);
   return rc;
}

static int client_send(struct connection *cnx, const char *type, const char *req, const uint8_t *data, size_t sz)
{
   int rc = 0;
   size_t send_sz = 0, slen = 0;
   char buffer[BUFFER_SZ] = {0};

   if ((rc = client_connect(cnx)) < 0)
      quit("Failed to connect");

   if (cnx->addr.status == CNX_UNSET) {
      /* not connected */
      goto out;
   }

   send_sz = sprintf(buffer, "%s "
                     "%s " HTTP_VERSION
#ifdef CONFIG_NO_KEEPALIVE
                     "Connection: close\r\n"
#endif
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n",
                     type, req, "localhost", "client 0.2");
   memcpy(buffer + send_sz, data, sz);
   send_sz += sz;
   buffer[send_sz++] = '\r';
   buffer[send_sz++] = '\n';
   buffer[send_sz] = '\0';
   debugf("Send %ld: <<END\n%s\nEND\n", send_sz, buffer);
   while (slen < send_sz) {
      if (cnx->addr.status == CNX_SSL) {
         while ((rc = ssl_write(&cnx->ssl, buffer + slen, send_sz - slen)) <= 0) {
            time_t t = time(NULL);
            if (rc == POLARSSL_ERR_NET_WANT_READ || rc == POLARSSL_ERR_NET_WANT_WRITE)
               continue;
            if (rc == 0)
               // It just didn't write anything
               continue;
            // Some kind of error, let's free the connection
            error_strerror(rc, buffer, 4096);
            errorf("[%02d:%02d.%02d] ssl write returned %d: %s", (t/3600)%24, (t/60)%60,
                   t%60, rc, buffer);
            connection_free(cnx);
            goto out;
         }
      } else if (cnx->addr.status == CNX_NORMAL) {
         while ((rc = send(cnx->sockfd, buffer + slen, send_sz - slen, 0)) <= 0) {
            time_t t = time(NULL);
            if (errno == -EAGAIN)
               continue;
            if (rc == 0)
               continue;
            connection_free(cnx);
            quitf("[%02d:%02d.%02d] send returned %d", (t/3600)%24, (t/60)%60, t%60, errno);
         }
      }
      slen += rc;
   }
 out:
   return rc;
}

static int client_get_cookies(char *buffer, struct client_ctx *ctx)
{
   int rc = 0;
   char *start = NULL, *end = NULL;
   int len = 0;

   if (!ctx) {
      return 0;
   }
   ctx->len = 0;
   memset(ctx->cookies, 0, COOKIE_BUFFER_LEN);
   end = buffer;
   do {
      if (!(start = strstr(end, "Set-Cookie"))) {
         break;
      }
      start += sizeof("Set-Cookie:") - 1;
      if (!(end = strstr(start, "\r\n"))) {
         len = strlen(start);
      } else {
         len = end - start;
      }
      if (ctx->len + len > COOKIE_BUFFER_LEN) {
         errorf("Cookie is too long (%d)", ctx->len + len);
         break;
      }
      memcpy(ctx->cookies + ctx->len, start, len);
      ctx->len += len;
      rc ++;
   } while (end);
   return rc;
}

static int client_recv(struct connection *cnx, uint8_t **ret, size_t *ret_sz, struct client_ctx *ctx)
{
   int rc = 0, needs_header = 1, done = 0;
   size_t recv_sz = 0, sz = 0;
   off_t roff = 0;
   char buffer[BUFFER_SZ] = {0}, *data = NULL, *tmp = NULL;
   struct pollfd fds;

   if (cnx->addr.status == CNX_UNSET)
      quit("Trying to recv an invalid connection");

   if (cnx->sockfd == -1)
      quit("Trying to recv on disconnected socket");

   if (cnx->addr.status == CNX_NORMAL) {
      fds = (struct pollfd){cnx->sockfd, POLLIN | POLLPRI, 0};
   }

   if (ret == NULL)
      quit("Bad argument");

   data = *(char **)ret;
   if (ret_sz && data) {
      sz = *ret_sz;
   } else {
      sz = BUFFER_SZ;
      data = realloc(data, sz);
      memset(data, 0, BUFFER_SZ);
   }

   do {
      if (cnx->addr.status == CNX_SSL) {
         while ((rc = ssl_read(&cnx->ssl, buffer + roff, BUFFER_SZ - roff)) <= 0) {
            time_t t = time(NULL);
            if (rc == POLARSSL_ERR_NET_WANT_READ || rc == POLARSSL_ERR_NET_WANT_WRITE)
               continue;
            if (rc == 0) {
               error("Connection closed?");
            }
            error_strerror(rc, buffer, BUFFER_SZ);
            errorf("[%02d:%02d.%02d] ssl read returned %d: %s", (t/3600)%24, (t/60)%60, t%60, rc, buffer);
            connection_free(cnx);
            goto out;
         }
      } else if (cnx->addr.status == CNX_NORMAL) {
         while ((rc = recv(cnx->sockfd, buffer + roff, BUFFER_SZ - roff, 0)) <= 0) {
            time_t t = time(NULL);
            if (rc < 0 && errno == -EAGAIN) {
               poll(&fds, 1, 100);
               continue;
            }
            if (rc == 0)
               error("Connection closed?");
            quitf("[%02d:%02d.%02d] recv returned %d", (t/3600)%24, (t/60)%60, t%60, errno);
         }
      }

      roff += rc;
      if (needs_header) {
         if ((tmp = strstr(buffer, "\r\n\r\n"))) {
            /* Finished reading the header */
            needs_header = 0;
            /* Skipping the new line */
            tmp += 2;
            *tmp++ = '\0'; *tmp++ = '\0';
            debugf("Found header:\n%s\n", buffer);
            client_get_cookies(buffer, ctx);
         } else {
            debug("Header incomplete");
            continue;
         }
      } else {
         tmp = buffer;
      }

      if (!strlen(tmp)) {
         done = 1;
         debug("Done");
      }

      while (!done) {
         rc = strtol(tmp, &tmp, 16);
         tmp += 2;
         if (rc > 0) {
            if (sz < recv_sz + rc + 1) {
               data = realloc(data, recv_sz + rc + 1);
               sz = recv_sz + rc + 1;
            }
            memcpy(data + recv_sz, tmp, rc);
            recv_sz += rc;
            tmp += rc;
         } else if (rc == 0) {
            done = 1;
         } else {
            done = 1;
            error("strtol failed");
         }
         tmp += 2;
      }
      roff -= (tmp - buffer);
      if (roff)
         memcpy(buffer, tmp, roff);
   } while (!done);

   rc = recv_sz;
   data[rc] = '\0';
   *ret = (uint8_t *)data;
   if (ret_sz)
      *ret_sz = sz;
   debugf("Returning %d bytes: %s", rc, data);

 out:
   if (rc < 0 && data) {
      free(data);
      if (ret) *ret = NULL;
   } else if (rc == 0) {
      debug("No data");
   }
#ifdef CONFIG_NO_KEEP_ALIVE
   connection_free(cnx);
#endif
   return rc;
}

static int
decode_base64_internal(uint8_t *dst, uint8_t *src, size_t src_sz,
                           const uint8_t *basis)
{
   size_t          len;
   uint8_t        *d, *s;

   for (len = 0; len < src_sz; len++) {
      if (src[len] == '=') {
         break;
      }

      if (basis[src[len]] == 77) {
         return -1;
      }
   }

   if (len % 4 == 1) {
      return -1;
   }

   s = src;
   d = dst;

   while (len > 3) {
      *d++ = (uint8_t) (basis[s[0]] << 2 | basis[s[1]] >> 4);
      *d++ = (uint8_t) (basis[s[1]] << 4 | basis[s[2]] >> 2);
      *d++ = (uint8_t) (basis[s[2]] << 6 | basis[s[3]]);

      s += 4;
      len -= 4;
   }

   if (len > 1) {
      *d++ = (uint8_t) (basis[s[0]] << 2 | basis[s[1]] >> 4);
   }

   if (len > 2) {
      *d++ = (uint8_t) (basis[s[1]] << 4 | basis[s[2]] >> 2);
   }

   return d - dst;
}

int decode_base64(uint8_t *dst, uint8_t *src, size_t src_sz)
{
   static uint8_t   basis64[] = {
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
      52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
      77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
      77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
   };

   return decode_base64_internal(dst, src, src_sz, basis64);
}

int encode_base64(uint8_t *dst, uint8_t *src, size_t src_sz)
{
   uint8_t        *d, *s;
   size_t          len;
   static uint8_t  basis64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   len = src_sz;
   s = src;
   d = dst;

   while (len > 2) {
      *d++ = basis64[(s[0] >> 2) & 0x3f];
      *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
      *d++ = basis64[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
      *d++ = basis64[s[2] & 0x3f];

      s += 3;
      len -= 3;
   }

   if (len) {
      *d++ = basis64[(s[0] >> 2) & 0x3f];

      if (len == 1) {
         *d++ = basis64[(s[0] & 3) << 4];
         *d++ = '=';

      } else {
         *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
         *d++ = basis64[(s[1] & 0x0f) << 2];
      }

      *d++ = '=';
   }

   return d - dst;
}
