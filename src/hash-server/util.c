#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/select.h>

#include "util.h"

void *Malloc(size_t sz)
{
   void *result = malloc(sz);
   if (result == NULL)
      die("Out of memory!\n");
   return result;
}

int read_all(int fd, void *buf, size_t count)
{
   uint8_t *the_buf = buf;
   while (count > 0) {
      ssize_t rc;
      rc = read(fd, the_buf, count);
      if (rc <= 0) {
         /* == 0 -> EOF before packet complete */
         return -1;
      }
      the_buf += rc;
      count -= rc;
   }
   return 0;
}

void debug_hex(uint8_t *buf, size_t sz)
{
   size_t i;
   for (i = 0; i < sz; i++) {
      debug("%02x", buf[i]);
   }
}

void error_hex(uint8_t *buf, size_t sz)
{
   size_t i;
   for (i = 0; i < sz; i++) {
      error("%02x", buf[i]);
   }
}
