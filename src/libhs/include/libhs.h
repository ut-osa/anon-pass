#ifndef _LIB_HS_H
#define _LIB_HS_H

#include <netinet/in.h>
#include <stdint.h>

#include <hash_server.h>

struct hs_conn;

/**
 * Create a new hash_server connection
 * ret: allocated hs_conn
 */
struct hs_conn *hs_connect(struct sockaddr_in *addr);
struct hs_conn *hs_connect_str(const char *host, int port);

/**
 * Performs a login request
 * ret: accept or reject
 */
int hs_login(struct hs_conn *hs, void *token);

/**
 * Performs a link request
 * ret: accept or reject
 */
int hs_link(struct hs_conn *hs, void *token, void *next_token);

int hs_get(struct hs_conn *hs, void *token, uint32_t *value_sz, void **value);

int hs_put(struct hs_conn *hs, void *token, uint32_t value_sz, void *value);

/**
 * Frees a hash_server connection
 */
void hs_disconnect(struct hs_conn *hs);

#endif
