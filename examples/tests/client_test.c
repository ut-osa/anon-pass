#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <anon-pass/anon-pass.h>
#include <anon-pass/client.h>
#include <anon-pass/debug.h>

#define DEFAULT_PORT 8080
#define DEFAULT_ADDR "0.0.0.0"
#define DEFAULT_URI_BASE "/pass"
#define DEFAULT_PARAMS "param/a.param"
#define RECV_BUFFER_SZ 4096

#if (DEBUG)
#define N_LOGIN 1
#define N_REUP 1
#else
#define N_LOGIN 4096
#define N_REUP  10240
#endif

#define quit(msg) do {                          \
      errorf("%s: " msg, strerror(errno));      \
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

enum {PARAMS, REG, REG_IN, LOGIN, REUP, MAX_TIMER};
make_timer(full, MAX_TIMER);

int client_connect(const char *host, int port);
int client_params(int sockfd, struct public_params *public_params);
int client_register(int sockfd, struct public_params *public_params,
                    struct client_secret *client_secret, struct register_sig *sig);
int client_login(int sockfd, struct public_params *public_params,
                    struct client_secret *client_secret, struct register_sig *sig);
int client_reup(int sockfd, struct public_params *public_params,
                struct client_secret *client_secret);

static int client_send(int sockfd, const char *req, const uint8_t *data);
static int client_recv(int sockfd, uint8_t **ret, size_t *ret_sz);

int decode_base64(uint8_t *dst, uint8_t *src, size_t src_sz);
int encode_base64(uint8_t *dst, uint8_t *src, size_t src_sz);

void callout_buffer(uint8_t *buffer, size_t sz);

static char *login_precompute = NULL;
static char *reup_precompute = NULL;

int main(int argc, char *argv[]) {
   int start_time = 0;
   int rc = 0, i;
   int sockfd = 0, port = 0;
   char *addr = DEFAULT_ADDR;
   char *client_keyfile = NULL;
   unsigned long start_login, start_reup;
   struct timeval t = {0,0};
   struct public_params public;
   struct client_secret client;
   struct register_sig server_sig;

   if (argc > 1) {
      addr = argv[1];
   }
   if (argc > 2) {
      port = strtod(argv[2], NULL);
   }
   if (argc > 3) {
      start_time = strtod(argv[1], NULL);
   }
   if (argc > 4) {
      client_keyfile = argv[3];
   }
   if ((rc = client_connect(addr, port)) < 0)
      quit("Failed to connect");
   sockfd = rc;

   pairing_init(public.p, fopen(DEFAULT_PARAMS, "r"));
   if ((rc = client_params(sockfd, &public)) < 0)
      quit("Failed to initialize public parameters");

   srand(getpid());
   /* Initialization */
   usleep((rand() % 20000) * 100);
   if (client_init(&public, &client, &server_sig,
                   client_keyfile != NULL ? fopen(client_keyfile,"a+") : NULL) != 2) {
      if ((rc = client_register(sockfd, &public, &client, &server_sig)) < 0)
         quit_loc(client, "Failed to register");
      if (client_save_reg_sig(&server_sig, client_keyfile != NULL ?     \
                              fopen(client_keyfile,"a+") : NULL) < 0)
         quit_loc(sig, "Failed to save signature");
   }
   usleep((rand() % 20000) * 100);
   if ((rc = client_login(sockfd, &public, &client, &server_sig)) < 0)
      quit_loc(sig, "Failed to login");
   usleep((rand() % 20000) * 100);
   if ((rc = client_reup(sockfd, &public, &client)) < 0)
      quit_loc(sig, "Failed to reup");

   gettimeofday(&t, NULL);
   if (t.tv_sec < start_time)
      usleep(1000000 * (start_time - t.tv_sec) - t.tv_usec);

#if (defined BENCH_LOGIN)
   for (i = 0; i < N_LOGIN; i++) {
      add_timer(full,LOGIN,
      if ((rc = client_login(sockfd, &public, &client, &server_sig)) < 0)
         quit_loc(sig, "Failed to login");
      );
   retry:
      usleep(100 * (rand() % 2000));
      if ((i+1) == 32) {
         close(sockfd);
         if ((rc = client_connect(addr, port)) < 0) {
            goto retry;
         }
         sockfd = rc;
      }
   }
   print_timer(full,LOGIN);
#elif (defined BENCH_REUP)
   for (i = 0; i < N_REUP; i++) {
      add_timer(full,REUP,
      if ((rc = client_reup(sockfd, &public, &client)) < 0)
         quit_loc(sig, "Failed to reup");
      );
   retry:
      usleep(100 * (rand() % 2000));
      if ((i+1) == 32) {
         close(sockfd);
         if ((rc = client_connect(addr, port)) < 0) {
            goto retry;
         }
         sockfd = rc;
      }
   }
   print_timer(full,REUP);
#endif

   rc = 0;
   if (login_precompute)
      free(login_precompute);
   if (reup_precompute)
      free(reup_precompute);
 out_sig:
   reg_sig_clear(&server_sig, 0);
 out_client:
   client_clear(&client);
   pub_clear(&public);
 out:
   if (sockfd > 0)
      close(sockfd);
   return rc;
}

/**
 * @in:  (const char *host) Server IP address, (int port) Server port
 * @out: (none)
 * @ret: socket fd
 */
int client_connect(const char *host, int port)
{
   int rc = 0, sockfd = 0;
   struct sockaddr_in addr;
   if ((rc = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      quit("Could not create socket");
   sockfd = rc;
   memset(&addr, 0, sizeof(addr));
   if (!port) {
      port = DEFAULT_PORT;
   }
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   if ((rc = inet_pton(AF_INET, host, &addr.sin_addr)) <= 0)
      quit("Could not translate addr");

   if ((rc = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr))) < 0)
      quit("Could not connect to server");
   rc = sockfd;
 out:
   return rc;
}

/**
 * @in:  (int sockfd) Connected socket
 * @out: (struct public_params *) Initialized public parameters
 * @ret: success or failure
 */
int client_params(int sockfd, struct public_params *public_params)
{
   int rc;
   uint8_t *buffer = NULL;
   size_t sz = 0, rsz = 0;
   off_t off = 0;

   if ((rc = client_send(sockfd, "params", (uint8_t *)"")) < 0)
      quit("Could not send params request");

   if ((rc = client_recv(sockfd, &buffer, &sz)) < 0)
      quit("Could not read params");
   rsz = rc;

   /* Unwrap Data */
   rsz = decode_base64(buffer, buffer, rsz);
   pub_init(public_params, NULL);
   off += element_from_bytes(public_params->g, buffer + off);
   off += element_from_bytes(public_params->gt, buffer + off);
   off += element_from_bytes(public_params->X, buffer + off);
   off += element_from_bytes(public_params->Y, buffer + off);
   off += element_from_bytes(public_params->Z, buffer + off);
 out:
   if (buffer)
      free(buffer);
   return rc;
}

int client_register(int sockfd, struct public_params *public_params,
                    struct client_secret *client_secret, struct register_sig *sig)
{
   int rc = 0;
   uint8_t *tmp = NULL, *buffer = NULL;
   size_t sz = 0, rsz = 0;
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

   sz = base64_encoded_length(off) + 1;
   buffer = malloc(sz);
   memset(buffer, 0, sz);
   off = encode_base64(buffer, tmp, off);

   if ((rc = client_send(sockfd, "register", buffer)) < 0)
      quit_loc(reg, "Could not send register message");

   if ((rc = client_recv(sockfd, &buffer, &sz)) < 0)
      quit_loc(reg, "Register recv failed");
   rsz = rc;

   if (rsz == 0)
      quit_loc(reg, "Registration rejected");

   /* Unwrap Data */
   reg_sig_init(public_params, sig);
   rsz = decode_base64(buffer, buffer, rsz);
   off = 0;
   off += element_from_bytes(sig->A,  buffer + off);
   off += element_from_bytes(sig->B,  buffer + off);
   off += element_from_bytes(sig->ZB, buffer + off);
   off += element_from_bytes(sig->C,  buffer + off);

   if ((rc = client_verify_reg_sig(public_params, client_secret, sig)) == 0) {
      reg_sig_clear(sig, 1);
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

int client_login(int sockfd, struct public_params *public_params,
                    struct client_secret *client_secret, struct register_sig *sig)
{
   int rc = 0;
   uint8_t *buffer = NULL, *tmp = NULL;
   size_t sz = 0, rsz = 0;
   off_t off = 0;
   struct login_msg msg;

#if (CACHE)
   if (login_precompute) {
      if ((rc = client_send(sockfd, "login", login_precompute)) < 0)
         quit("Could not send login message");

      if ((rc = client_recv(sockfd, &buffer, &sz)) < 0)
         quit("Login recv failed");
      rsz = rc;
      goto out;
   }
#endif
   if (!client_create_login_msg(public_params, client_secret, sig, &msg, 0))
      quit("Could not create login message");

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

   sz = base64_encoded_length(off) + 1;
   buffer = malloc(sz);
   if (!buffer)
      quit_loc(msg, "Could not allocate memory");
   memset(buffer, 0, sz);
   off = encode_base64(buffer, tmp, off);
   buffer[sz - 1] = '\0';

#if (CACHE)
   if (!login_precompute) {
      login_precompute = malloc(sz);
      memcpy(login_precompute, buffer, sz);
   }
#endif

   if ((rc = client_send(sockfd, "login", buffer)) < 0)
      quit_loc(msg, "Could not send login message");

   if ((rc = client_recv(sockfd, &buffer, &sz)) < 0)
      quit_loc(msg, "Login recv failed");
   rsz = rc;

   if (rsz == 0)
      quit_loc(msg, "Login rejected");

 out_msg:
   login_msg_clear(&msg);
 out:
   if (tmp)
      free(tmp);
   if (buffer)
      free(buffer);

   return rc;
}

int client_reup(int sockfd, struct public_params *public_params,
                struct client_secret *client_secret)
{
   int rc = 0;
   uint8_t *buffer = NULL, *tmp = NULL;
   size_t sz = 0, rsz = 0;
   off_t off = 0;
   struct reup_msg msg;

#if (CACHE)
   if (reup_precompute) {
      if ((rc = client_send(sockfd, "reup", reup_precompute)) < 0)
         quit("Could not send reup message");

      if ((rc = client_recv(sockfd, &buffer, &sz)) < 0)
         quit("Reup recv failed");
      rsz = rc;
      goto out;
   }
#endif

   if (!client_create_reup_msg(public_params, client_secret, &msg, 0))
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

   sz = base64_encoded_length(off) + 1;
   buffer = malloc(sz);
   if (!buffer)
      quit_loc(msg, "Could not allocate memory");
   memset(buffer, 0, sz);
   off = encode_base64(buffer, tmp, off);
   buffer[sz - 1] = '\0';

#if (CACHE)
   if (!reup_precompute) {
      reup_precompute = malloc(sz);
      memcpy(reup_precompute, buffer, sz);
   }
#endif

   if ((rc = client_send(sockfd, "reup", buffer)) < 0)
      quit_loc(msg, "Could not send reup message");

   if ((rc = client_recv(sockfd, &buffer, &sz)) < 0)
      quit_loc(msg, "Reup recv failed");
   rsz = rc;

   if (rsz == 0)
      quit_loc(msg, "Reup rejected");
 out_msg:
   reup_msg_clear(&msg);
 out:
   if (tmp)
      free(tmp);
   if (buffer)
      free(buffer);

   return rc;
}

static int client_send(int sockfd, const char *req, const uint8_t *data)
{
   int rc = 0;
   size_t send_sz = 0, slen = 0;
   char buffer[4096] = {0};

   send_sz = sprintf(buffer, "GET "DEFAULT_URI_BASE
                     "/%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Cookie: data=%s;\r\n"
                     "User-Agent: %s\r\n\r\n",
                     req, "localhost", data, "client 0.1");

   buffer[send_sz] = '\0';
   debugf("Send %ld: <<END\n%s\nEND\n", send_sz, buffer);
   while (slen < send_sz) {
      /* Possibly turn this into datagram */
      if ((rc = send(sockfd, buffer + slen, send_sz - slen, 0)) <= 0)
         quit("Failed to send");
      slen += rc;
   }
 out:
   return rc;
}

static int set_nonblock(int sockfd)
{
   int fl = fcntl(sockfd, F_GETFL);
   fcntl(sockfd, F_SETFL, fl | O_NONBLOCK);
   return sockfd;
}

static int client_recv(int sockfd, uint8_t **ret, size_t *ret_sz)
{
   int rc = -1, has_header = 1, done = 0;
   size_t recv_sz = 0, sz = 0;
   char buffer[RECV_BUFFER_SZ] = {0}, *data = NULL, *tmp = NULL;
   struct pollfd fds = {sockfd, POLLIN | POLLPRI, 0};

   if (!ret)
      quit("Bad argument");

   data = *(char **)ret;
   if (ret_sz && data) {
      sz = *ret_sz;
   } else {
      sz = RECV_BUFFER_SZ;
      data = realloc(data, sz);
      memset(data, 0, RECV_BUFFER_SZ);
   }

   sockfd = set_nonblock(sockfd);
   do {
      rc = recv(sockfd, buffer, RECV_BUFFER_SZ, 0);
      if (rc < 0 && errno == EAGAIN) {
         poll(&fds, 1, 100);
         continue;
      } else if (rc == 0) {
         /* Connection Closed */
         errno = -EPERM;
         break;
      } else if (rc < 0)
         quit("Failed to recv data");

      if (has_header) {
         if ((tmp = strstr(buffer, "\r\n\r\n"))) {
            has_header = 0;
            *tmp = '\0';
            tmp += 4;
            debugf("Found header:\n%s\n\n", buffer);
         }
      } else {
         tmp = buffer;
      }

      /* Is it valid to assume the chunks won't split recv's? */
      do {
         rc = strtol(tmp, &tmp, 16);
         tmp += 2;
         if (rc) {
            if (sz < recv_sz + rc + 1) {
               data = realloc(data, recv_sz + rc + 1);
               sz = recv_sz + rc + 1;
            }
            memcpy(data + recv_sz, tmp, rc);
            recv_sz += rc;
            tmp += rc;
         } else {
            done = 1;
         }
      } while (rc);
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
   }
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

void callout_buffer(uint8_t *buffer, size_t sz)
{
   size_t i;
   fprintf(stderr, "\n\n@@@\n");
   for (i = 0; i < sz; i++) {
      fprintf(stderr, "%02x", (uint8_t)buffer[i]);
      if ((i + 1) % 32 == 0) fprintf(stderr, "\n");
      else if ((i + 1) % 8 == 0) fprintf(stderr, "\t");
      else if ((i + 1) % 2 == 0) fprintf(stderr, " ");
   }
   if (i % 32) fprintf(stderr, "\n");
   fprintf(stderr, "@@@\n\n");
}
