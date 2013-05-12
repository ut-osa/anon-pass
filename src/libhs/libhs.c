#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <hash_server.h>
#include <libhs.h>

struct hs_conn {
   int fd;
   struct sockaddr_in addr;
};

/* XXX: I figure it is not worth creating a whole extra library for
   these two functions... */
#define die(fmt, args...) do { error(fmt, ##args); exit(1); } while(0)

void *Malloc(size_t sz)
{
   void *result = malloc(sz);
   if (result == NULL)
      die("Out of memory!\n");
   return result;
}

static int __hs_connect(struct hs_conn *hs)
{
   int flag = 1;
   int fd = socket(AF_INET, SOCK_STREAM, 0);
   if (fd < 0)
      goto fail;

   if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
      die("setsockopt failed\n");
   }

   if (connect(fd, (struct sockaddr *)&hs->addr, sizeof(hs->addr)) < 0)
      goto fail;
   hs->fd = fd;

   return fd;
 fail:
   fprintf(stderr, "Failed to connect to hash server\n");
   return -1;
}

struct hs_conn *hs_connect(struct sockaddr_in *addr)
{
   struct hs_conn *result = NULL;

   result = Malloc(sizeof(*result));
   result->fd = -1;
   memcpy(&result->addr, addr, sizeof(*addr));

   return result;
}

struct hs_conn *hs_connect_str(const char *host, int port)
{
   struct hs_conn *result = NULL;
   struct sockaddr_in addr;

   memset(&addr, 0, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
      goto out;
   result = hs_connect(&addr);

 out:
   return result;
}

int hs_login(struct hs_conn *hs, void *token)
{
   uint8_t buf[HS_ENTRY_LEN+sizeof(uint8_t)];
   uint8_t result;
   buf[0] = CMD_LOGIN;
   memcpy(buf+1, token, HS_ENTRY_LEN);

   if (hs->fd < 0 && __hs_connect(hs) < 0) {
      return -1;
   }

   if (write(hs->fd, buf, sizeof(buf)) != sizeof(buf))
      return -1;

   if (read(hs->fd, &result, sizeof(result)) != sizeof(result))
      return -1;

   if (result != 0 && result != 1)
      return -1;

   return result;
}

int hs_link(struct hs_conn *hs, void *prev_token, void *next_token)
{
   uint8_t buf[sizeof(uint8_t)+2*HS_ENTRY_LEN];
   uint8_t result;
   buf[0] = CMD_LINK;
   memcpy(buf+1, prev_token, HS_ENTRY_LEN);
   memcpy(buf+1+HS_ENTRY_LEN, next_token, HS_ENTRY_LEN);

   if (hs->fd < 0 && __hs_connect(hs) < 0) {
      fprintf(stderr, "Failed to connect hs\n");
      return -1;
   }

   if (write(hs->fd, buf, sizeof(buf)) != sizeof(buf)) {
      fprintf(stderr, "Failed to write request\n");
      return -1;
   }

   if (read(hs->fd, &result, sizeof(result)) != sizeof(result)) {
      fprintf(stderr, "Failed to read result\n");
      return -1;
   }

   if (result != 0 && result != 1) {
      fprintf(stderr, "Improper result %d\n", result);
      return -1;
   }

   return result;
}

int hs_get(struct hs_conn *hs, void *token, uint32_t *value_sz, void **value)
{
   uint8_t buf[sizeof(uint8_t)+HS_ENTRY_LEN];
   uint8_t result;
   uint32_t the_sz;

   buf[0] = CMD_GET;
   memcpy(buf+1, token, HS_ENTRY_LEN);

   if (hs->fd < 0 && __hs_connect(hs) < 0) {
      fprintf(stderr, "Failed to connect hs\n");
      return -1;
   }

   if (write(hs->fd, buf, sizeof(buf)) != sizeof(buf))
      return -1;

   if (read(hs->fd, &result, sizeof(result)) != sizeof(result))
      return -1;

   if (result == 1 && value != NULL) {
      if (read(hs->fd, &the_sz, sizeof(the_sz)) != sizeof(the_sz))
         return -1;
      *value = Malloc(the_sz);
      if (read(hs->fd, *value, the_sz) != the_sz) {
         free(*value);
         return -1;
      }
      if (value_sz)
         *value_sz = the_sz;
   }

   return result;
}

int hs_put(struct hs_conn *hs, void *token, uint32_t value_sz, void *value)
{
   uint8_t buf[sizeof(uint8_t)+HS_ENTRY_LEN];

   buf[0] = CMD_PUT;
   memcpy(buf+1, token, HS_ENTRY_LEN);

   if (hs->fd < 0 && __hs_connect(hs) < 0) {
      fprintf(stderr, "Failed to connect hs\n");
      return -1;
   }

   if (write(hs->fd, buf, sizeof(buf)) != sizeof(buf))
      return -1;

   if (write(hs->fd, &value_sz, sizeof(value_sz)) != sizeof(value_sz))
      return -1;

   if (write(hs->fd, value, value_sz) != value_sz)
      return -1;

   return 1;
}

void hs_disconnect(struct hs_conn *hs)
{
   close(hs->fd);
   free(hs);
}
