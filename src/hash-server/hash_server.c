#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/time.h>
#include <string.h>

#include <hash_server.h>

#include "util.h"
#include "hash.h"

#ifdef LOGGING
#define LOG_EARLY  4
#define LOG_LATE   5
static uint64_t count[4] = {0};
static uint64_t pass[6] = {0};
static idle = 0;

static FILE *log = NULL;
#endif

struct options {
   int port;
   int epoch_len;
   int timeout_len;
   int flag;
} options;

struct conn {
   int id;
   int sock_fd;

   pthread_t thread;
   struct server *s;
};

struct server {
   int listen_fd;

   /* XXX: fairness for semaphores sounds like (from POSIX spec) by
      longest wait (= queue), which is what we want, but untested in
      practice...
   */
   /* XXX: fine-grained (per-key) locking? */
   sem_t ht_lock;
   pthread_t epoch_thread;
   struct hash_table *ht, *next_ht;
};

#define FLAG_NOOP (1<<0)
#define FLAG_NO_HASH (1<<1)

void *handle_epoch_changes(void *arg);

void init_server(struct server *s)
{
   int i, rc;
   struct sockaddr_in addr;

   s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
   if (s->listen_fd < 0)
      die("socket\n");

   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = htonl(INADDR_ANY);
   addr.sin_port = htons(options.port);
   rc = bind(s->listen_fd, (struct sockaddr *)&addr, sizeof(addr));
   if (rc < 0)
      die("bind\n");

   rc = listen(s->listen_fd, 5);
   if (rc < 0)
      die("listen\n");

   s->ht = create_hash_table();
   if (!s->ht)
      die("failed to create hash table\n");
   s->next_ht = NULL;

   rc = sem_init(&s->ht_lock, 0, 1);
   if (rc < 0)
      die("sem_init");

   if (pthread_create(&s->epoch_thread, NULL,
                      handle_epoch_changes, (void *)s) < 0)
      die("pthread_create");
}

int handle_login(struct server *s, struct conn *c)
{
   int rc = -1;
   int sock_fd = c->sock_fd;
   uint8_t token[HS_ENTRY_LEN];
   uint8_t result = 1;
   static uint64_t l = 0;
   struct timeval now;

   if (read_all(sock_fd, token, HS_ENTRY_LEN) < 0) {
      error("malformed login packet (id %d)\n", c->id);
      goto out;
   }
   if (options.flag & FLAG_NOOP) goto out_write;

   rc = sem_wait(&s->ht_lock);
   if (rc < 0) {
      error("cannot wait in handle_login? (id %d)\n", c->id);
      goto out;
   }
#ifdef LOGGING
   count[CMD_LOGIN] ++;
#endif
   if (options.flag & FLAG_NO_HASH) goto out_unlock;

   debug("login: ");
   debug_hex(token, HS_ENTRY_LEN);
   debug("\n");
   l ++;

   /* What are the sematics for the just a little old hash table? */
   if (contains_key(s->ht, token)) {
      gettimeofday(&now, NULL);
      debug("[% 4ld] Login duplicate - %02ld:%02ld.%02ld: ", l,
            (now.tv_sec / 3600) % 24, (now.tv_sec / 60) % 60, now.tv_sec % 60);
      debug_hex(token, HS_ENTRY_LEN);
      debug("\n");
      result = 0;
   } else {
      uint64_t timeout = unow() + options.timeout_len;
      add_key(s->ht, token, timeout);
      if (s->next_ht) {
         add_key(s->next_ht, token, timeout);
      }
      result = 1;
#ifdef LOGGING
      pass[CMD_LOGIN] ++;
#endif
   }

 out_unlock:
   rc = sem_post(&s->ht_lock);
   if (rc < 0) {
      /* this would permanently lock, so die */
      die("sem_post");
   }

#if (BENCHMARK)
   result = 1;
#endif
 out_write:
   if (write(sock_fd, &result, sizeof(result)) != sizeof(result)) {
      /* XXX: what do we do here? */
      error("couldn't return login result (id %d)\n", c->id);
   }

   rc = 0;

 out:
   return rc;
}

int handle_link(struct server *s, struct conn *c)
{
   int rc = -1;
   int sock_fd = c->sock_fd;
   uint8_t tokens[2*HS_ENTRY_LEN];
   uint8_t *token1 = tokens;
   uint8_t *token2 = tokens + HS_ENTRY_LEN;
   uint8_t result = 1;
   uint32_t sz = 0;
   uint64_t t = 0;
   void *value = NULL;
   struct timeval now;

   if (read_all(sock_fd, tokens, sizeof(tokens)) < 0) {
      error("malformed link packet (id %d)\n", c->id);
      goto out;
   }
   if (options.flag & FLAG_NOOP) goto out_write;

   rc = sem_wait(&s->ht_lock);
   if (rc < 0) {
      error("cannot wait in handle_link? (id %d)\n", c->id);
      goto out;
   }
#ifdef LOGGING
   count[CMD_LINK] ++;
#endif
   if (options.flag & FLAG_NO_HASH) goto out_unlock;

   debug("link: ");
   debug_hex(token1, HS_ENTRY_LEN);
   debug(" ");
   debug_hex(token2, HS_ENTRY_LEN);
   debug("\n");

   result = 0;
   if (!ht_get(s->ht, token1, &sz, &value) && sz != sizeof(t)) {
      gettimeofday(&now, NULL);
      debug(" Not authorized - %02ld:%02ld.%02ld\n",
            (now.tv_sec / 3600) % 24, (now.tv_sec / 60) % 60, now.tv_sec % 60);
   } else {
      memcpy(&t, value, sz);
      if (contains_key(s->ht, token2)) {
            gettimeofday(&now, NULL);
            debug(" Link duplicate - %02ld:%02ld.%02ld\n",
                  (now.tv_sec / 3600) % 24, (now.tv_sec / 60) % 60, now.tv_sec % 60);
      } else {
         uint64_t now = unow();
         if (now <= t && t < now + options.timeout_len) {
            t += options.timeout_len;
            add_key(s->ht, token2, t);
            if (s->next_ht) {
               add_key(s->next_ht, token2, t);
            }
            result = 1;
#ifdef LOGGING
         } else if (now > t) {
            pass[LOG_LATE] ++;
         } else if (t >= now + options.timeout_len) {
            pass[LOG_EARLY] ++;
         } else {
            fprintf(stderr, "LKJSDFLKJSDFLKJ\n");
#endif
         }
      }
   }
#ifdef LOGGING
   pass[CMD_LINK] += result;
#endif

 out_unlock:
   rc = sem_post(&s->ht_lock);
   if (rc < 0) {
      /* this would permanently lock, so die */
      die("sem_post");
   }

#if (BENCHMARK)
   result = 1;
#endif
 out_write:
   if (write(sock_fd, &result, sizeof(result)) != sizeof(result)) {
      error("couldn't return login result (id %d)\n", c->id);
      rc = -1;
      goto out;
   }

   rc = 0;

 out:
   if (value)
      free(value);
   return rc;
}

int handle_get(struct server *s, struct conn *c)
{
   int rc = -1;
   int sock_fd = c->sock_fd;
   uint8_t token[HS_ENTRY_LEN];
   void *value = NULL;
   uint32_t value_sz = 0;
   uint8_t result = 1;

   if (read_all(sock_fd, token, sizeof(token)) < 0) {
      error("malformed get packet (id %d)\n", c->id);
      goto out;
   }
   if (options.flag & FLAG_NOOP) goto out_write;

   rc = sem_wait(&s->ht_lock);
   if (rc < 0) {
      error("cannot wait in handle_get? (id %d)\n", c->id);
      goto out;
   }
#ifdef LOGGING
   count[CMD_GET] ++;
#endif
   if (options.flag & FLAG_NO_HASH) goto out_unlock;

   debug("get: ");
   debug_hex(token, HS_ENTRY_LEN);
   debug("\n");

   result = 0;
   if (ht_get(s->ht, token, &value_sz, &value) > 0) {
      result = 1;
#ifdef LOGGING
      pass[CMD_GET] ++;
#endif
   }

 out_unlock:
   rc = sem_post(&s->ht_lock);
   if (rc < 0) {
      die("sem_post");
   }

 out_write:
   if (write(sock_fd, &result, sizeof(result)) != sizeof(result)) {
      /* XXX: what do we do here? */
      error("couldn't return get result (id %d)\n", c->id);
      rc = -1;
      goto out;
   }

   if (result && value_sz) {
      debug(" => ");
      debug_hex(value, value_sz);
      debug("\n");
      /* if the get is successful, then we need to send back that too */
      if ((write(sock_fd, &value_sz, sizeof(value_sz)) != sizeof(value_sz)) ||
          (write(sock_fd, value, value_sz) != value_sz)) {
         error("couldn't write get value back (id %d)\n", c->id);
         rc = -1;
         goto out;
      }
   }

   rc = 0;

 out:
   if (value)
      free(value);

   return rc;
}

int handle_put(struct server *s, struct conn *c)
{
   int rc = -1;
   int sock_fd = c->sock_fd;
   uint8_t token[HS_ENTRY_LEN];
   const char misread_msg[] = "malformed put packet (id %d)\n";
   void *value;
   uint32_t value_sz;

   if ((read_all(sock_fd, token, sizeof(token)) < 0) ||
       (read_all(sock_fd, &value_sz, sizeof(value_sz)) < 0)) {
      error(misread_msg, c->id);
      goto out;
   }

   /* we could just cause this client to drop if we can't allocate
      memory */
   value = Malloc(value_sz);
   if (read_all(sock_fd, value, value_sz) < 0) {
      error(misread_msg, c->id);
      goto out;
   }
   if (options.flag & FLAG_NOOP) goto out;

   rc = sem_wait(&s->ht_lock);
   if (rc < 0) {
      error("cannot wait in handle_put? (id %d)\n", c->id);
      goto out;
   }
#ifdef LOGGING
   count[CMD_PUT] ++;
#endif
   if (options.flag & FLAG_NO_HASH) goto out_unlock;

   debug("put: ");
   debug_hex(token, HS_ENTRY_LEN);
   debug("\n");

   ht_put(s->ht, token, value_sz, value);
   if (s->next_ht)
      ht_put(s->next_ht, token, value_sz, value);

#ifdef LOGGING
   pass[CMD_PUT] ++;
#endif
 out_unlock:
   rc = sem_post(&s->ht_lock);
   if (rc < 0) {
      die("sem_post");
   }

 out:
   if (value)
      free(value);

   return rc;
}

/* You must lock around the hash table part of each operation */
int handle_request(struct server *s, struct conn *c)
{
   uint8_t cmd_type;
   int sock_fd = c->sock_fd;

   if (read_all(sock_fd, &cmd_type, sizeof(cmd_type)) < 0) {
      debug("disconnected (id %d)\n", c->id);
      return -1;
   }

   switch (cmd_type) {
   case CMD_LOGIN:
      return handle_login(s, c);
      break;
   case CMD_LINK:
      return handle_link(s, c);
      break;
   case CMD_GET:
      return handle_get(s, c);
      break;
   case CMD_PUT:
      return handle_put(s, c);
      break;
   default:
      error("unknown command %d (id %d)\n", cmd_type, c->id);
   }

   return -1;
}

void *handle_requests(void *arg)
{
   struct conn *c = arg;
   struct server *s = c->s;

   while (handle_request(s, c) >= 0) {}

   close(c->sock_fd);
   free(c);
   return NULL;
}

/* The way this is designed we can make the timing more accurate if
   desired - can prevent drift (from time taken by anything done in
   epoch change and scheduling) by always sleeping until the next
   epoch. */
static time_t epoch_start;
static void set_epoch_start(void)
{
   /*
     Forcing the epoch to start at a multiple of epoch length after
     the Epoch.
     Everyone else was doing it...
   */
   epoch_start = time(NULL) / options.epoch_len * options.epoch_len;
   printf("Epoch 0 begins at t=%lu\n", epoch_start);
}

static void sleep_until_next_epoch(void)
{
   time_t current_time = time(NULL);
   int time_left;

   time_left = options.epoch_len - ((current_time - epoch_start) % options.epoch_len);
   sleep(time_left);
}

void *handle_epoch_changes(void *arg)
{
   int rc;
   struct server *s = arg;
   struct hash_table *new_ht, *old_ht;
   struct timeval now;
   int iter = 0;

   set_epoch_start();

   while (1) {
      sleep_until_next_epoch();
      iter ++;
      gettimeofday(&now, NULL);
      debug("Epoch change - %02ld:%02ld.%02ld\n", (now.tv_sec / 3600) % 24, (now.tv_sec / 60) % 60, now.tv_sec % 60);

#ifdef LOGGING
      if (idle) {
         for (rc = 0; rc < 4; rc++) {
            if (count[rc]) {
               idle = 0;
               break;
            }
         }
      }
      if (idle < 16) {
         fprintf(log, "[%ld] ", now.tv_sec);
         for (rc = 0; rc < 4; rc++) {
            if (count[rc] == 0) {
               idle ++;
            }
            if (rc == CMD_LINK) {
               fprintf(log, "%ld < %ld > %ld|%ld", pass[LOG_EARLY], pass[rc], pass[LOG_LATE], count[rc]);
            } else {
               fprintf(log, "%ld|%ld", pass[rc], count[rc]);
            }
            if (rc < 3) {
               fprintf(log, "\t");
            }
         }
         fprintf(log, "\n");
         memset(pass, 0, sizeof(pass));
         memset(count, 0, sizeof(count));
         fflush(log);
      }
#endif

      /* Sleep a couple and then respond */
      if ((iter + 1) % 3 != 0) {
         continue;
      }

      if (!s->next_ht) {
         new_ht = create_hash_table();
         if (!new_ht)
            die("cannot make new hash table for next epoch?\n");

         rc = sem_wait(&s->ht_lock);
         if (rc < 0)
            die("cannot wait in handle_epoch_changes?\n");

         s->next_ht = new_ht;
         old_ht = NULL;
      } else {
         rc = sem_wait(&s->ht_lock);
         if (rc < 0)
            die("cannot wait in handle_epoch_changes?\n");

         old_ht = s->ht;
         s->ht = s->next_ht;
         s->next_ht = NULL;
      }
      rc = sem_post(&s->ht_lock);
      if (rc < 0) {
         /* this would permanently lock, so die */
         die("sem_post");
      }
      if (old_ht)
         destroy_hash_table(old_ht);
      old_ht = NULL;
   }
}

int process_args(int argc, char *argv[])
{
   int on_arg = 1;

   /* Set option defaults */
   /* Default epoch length is 5 minutes */
   options.epoch_len = 300;
   options.port = DEFAULT_HASH_SERVER_PORT;
   options.flag = 0;

   for (on_arg = 1; on_arg < argc; on_arg++) {
      if (strcmp(argv[on_arg], "-e") == 0) {
         if (++on_arg < argc)
            options.epoch_len = strtod(argv[on_arg], NULL);
      } else if (strcmp(argv[on_arg], "-p") == 0) {
         if (++on_arg < argc)
            options.port = strtod(argv[on_arg], NULL);
      } else if (strcmp(argv[on_arg], "--noop") == 0) {
         options.flag |= FLAG_NOOP;
      } else if (strcmp(argv[on_arg], "--no-hash") == 0) {
         options.flag |= FLAG_NO_HASH;
      } else if (strcmp(argv[on_arg], "-h") == 0) {
         return -2;
      } else {
         error("Unknown option: %s\n", argv[on_arg]);
         return -1;
      }
   }
   options.timeout_len = 1000000 * options.epoch_len;

   printf("Epoch length: %d s\n", options.epoch_len);
   printf("Listening on port %d...\n", options.port);

   return 0;
}

void usage(char *prog_name)
{
   printf("Usage: %s [OPTION]...\n"
          "   -e <epoch len (in s) | 300>\n"
          "   -p <port | 6666>\n", prog_name);
}

int main(int argc, char *argv[])
{
   struct server s;
   int next_id = 1;
   int flag = 1;
   int pa_rc;
   struct timeval now;

   if ((pa_rc = process_args(argc, argv)) < 0) {
      usage(argv[0]);
      exit(pa_rc == -2 ? 0 : 1);
   }

#ifdef LOGGING
   log = fopen("logs/hs_ops.log", "a");
   if (!log) {
       fprintf(stderr, "Could not open log location!\n");
       exit(-1);
   }
   gettimeofday(&now, NULL);
   fprintf(log, "[%ld] ", now.tv_sec);
   fprintf(log, "login\tlink\tput\tget\n");
   fflush(log);
#endif

   init_server(&s);

   while (1) {
      int fd;
      fd = accept(s.listen_fd, NULL, NULL);

      if (fd < 0)
         die("accept");

      if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
         die("setsockopt failed\n");
      }
      debug("new connection (id %d)\n", next_id);

      struct conn *c = Malloc(sizeof(*c));
      c->sock_fd = fd;
      c->id = next_id;
      next_id++;

      c->s = &s;
      if (pthread_create(&c->thread, NULL, handle_requests, (void *)c) < 0) {
         error("couldn't create thread (id %d)\n", c->id);
         free(c);
      }
   }
}
