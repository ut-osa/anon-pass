#ifndef _HASH_SERVER_HASH_H
#define _HASH_SERVER_HASH_H

#include <hash_server.h>

#include <stdint.h>
#include <glib.h>

struct hash_table;

struct hash_table *create_hash_table(void);

uint64_t unow();

int ht_get(struct hash_table *ht, void *token, uint32_t *value_sz, void **value);
void ht_put(struct hash_table *ht, void *token, uint32_t value_sz, void *value);

int contains_key(struct hash_table *ht, void *token);
/* Note: This will replace a key if it is already in the table */
void add_key(struct hash_table *ht, void *token, uint64_t timeout);

void destroy_hash_table(struct hash_table *ht);

#endif
