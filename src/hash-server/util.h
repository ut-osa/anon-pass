#ifndef _HASH_SERVER_UTIL_H
#define _HASH_SERVER_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//#define DEBUG

#define max(a, b) ((a) >= (b) ? (a) : (b))

#ifdef DEBUG
# define debug(fmt, args...) printf(fmt, ##args)
#else
# define debug(fmt, args...) do {} while(0)
#endif

#define error(fmt, args...) fprintf(stderr, fmt, ##args)
#define die(fmt, args...) do { error(fmt, ##args); exit(1); } while(0)

void *Malloc(size_t sz);
void debug_hex(uint8_t *buf, size_t sz);
void error_hex(uint8_t *buf, size_t sz);

/* keep reading from an fd until count bytes are read in total or an
   error occurs */
int read_all(int fd, void *buf, size_t count);

#endif
