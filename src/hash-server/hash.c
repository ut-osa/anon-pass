#include <string.h>
#include <glib.h>

#include "hash.h"
#include "util.h"

struct sized_blob {
   uint32_t sz;
   uint8_t blob[0];
} __attribute__((packed));

struct hash_table {
   GHashTable *ght;
};

uint64_t unow()
{
   struct timeval now;
   gettimeofday(&now, NULL);
   return now.tv_sec * 1000000 + now.tv_usec;
}

guint token_hash(gconstpointer key)
{
   /* We assume tokens are at least sizeof(guint) in length.  Then the
      bytes in a token are supposed to be "random looking" anyway, so
      why not use a part of the token? */
   return *(guint *)key;
}

gboolean token_cmp(gconstpointer a,
                   gconstpointer b)
{
   return (memcmp(a, b, HS_ENTRY_LEN) == 0);
}

void token_free(gpointer k)
{
   free(k);
}

void value_free(gpointer v)
{
   if (v)
      free(v);
}

struct hash_table *create_hash_table(void)
{
   struct hash_table *ht = Malloc(sizeof(*ht));

   ht->ght = g_hash_table_new_full(token_hash, token_cmp, token_free, value_free);
   if (ht->ght == NULL) {
      /* Can this actually happen? */
      free(ht);
      return NULL;
   }

   return ht;
}

int ht_get(struct hash_table *ht, void *token, uint32_t *value_sz, void **value)
{
   int rc;
   struct sized_blob *result;

   rc = g_hash_table_lookup_extended(ht->ght, token, NULL, (gpointer *)&result);

   if (rc && value) {
      /* found the key and the user wants the value */
      if (value_sz)
         *value_sz = result->sz;

      *value = Malloc(result->sz);
      memcpy(*value, &result->blob, result->sz);
   }

   debug("ht_get: %d\n", rc);

   return rc;
}

void ht_put(struct hash_table *ht, void *token, uint32_t value_sz, void *value)
{
   void *my_token = Malloc(HS_ENTRY_LEN);
   void *my_value = NULL;

   memcpy(my_token, token, HS_ENTRY_LEN);

   if (value) {
      struct sized_blob *sb = Malloc(sizeof(uint32_t) + value_sz);
      sb->sz = value_sz;
      memcpy(&sb->blob, value, value_sz);
      my_value = sb;
   }

   g_hash_table_insert(ht->ght, my_token, my_value);
}

int contains_key(struct hash_table *ht, void *token)
{
   uint64_t t;
   uint32_t sz;
   void *value = NULL;
   int rc = 0;
   rc = ht_get(ht, token, &sz, &value);
   if (rc && sz == sizeof(t)) {
      memcpy(&t, value, sz);
      rc = unow() < t;
   }
   if (value) {
      free(value);
   }
   return rc;
}

void add_key(struct hash_table *ht, void *token, uint64_t timeout)
{
   /* Insert a timeout */
   if (timeout) {
      ht_put(ht, token, sizeof(timeout), &timeout);
   } else {
      ht_put(ht, token, 0, NULL);
   }
}

void destroy_hash_table(struct hash_table *ht)
{
   g_hash_table_destroy(ht->ght);
   free(ht);
}
