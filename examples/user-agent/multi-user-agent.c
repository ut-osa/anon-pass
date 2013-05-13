#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <anon-pass/debug.h>
#include "agent-util.h"

enum {PARAMS, REG, REG_IN, LOGIN, REUP, MAX_TIMER};
make_timer(full, MAX_TIMER);

struct service_conf {
   /* Benchmark Params */
   int bench_mix;
   int no_processes;
   int no_connections;
   int no_requests;
   char params[256];
   char pubkey[256];
   /* Connection Params */
   struct addr_conf auth;
   uint64_t timeout;
   struct public_params public;
   struct client_secret client;
   struct register_sig sig;
};
int read_config(FILE *file, struct service_conf *service);

int start_connections(struct service_conf *service);
void *client_thread(void *arg);
int main(int argc, char *argv[]) {
   int i, rc = 0, spacer = 0;
   pid_t pid;
   pid_t *children = NULL;
   char *conf = DEFAULT_BENCH_CONF;
   time_t s;
   struct service_conf service = {
      .auth = {CNX_UNSET, 0, {0}, {NULL}},
      .timeout = 1000000 * DEFAULT_TIMEOUT,
      .pubkey = {0},
      .params = DEFAULT_PARAMS,
      .no_requests = 10,
      .no_connections = 10,
      .no_processes = 1,
      .bench_mix = 100,
   };

   if (argc > 1) {
      conf = argv[1];
   }

   read_config(fopen(conf, "r"), &service);
   debugf("service.no_processes: %d", service.no_processes);
   debugf("service.no_connections: %d", service.no_connections);
   debugf("service.no_requests: %d", service.no_requests);
   debugf("service.params: %s", service.params);
   debugf("service.pubkey: %s", service.pubkey);
   for (i = 0; i < service.auth.num; i++) {
      debugf("service.auth: %s:%d %s", service.auth.host[i], service.auth.port[i],
             service.auth.status == CNX_UNSET ?                         \
             "not connected" : (service.auth.status == CNX_NORMAL ?     \
                                "http connection" : "ssl connection"));
   }
   debugf("service.timeout: %d s", service.timeout / 1000000);

   s = time(NULL);
   outputf("[%02d:%02d.%02d] Start", (s / 3600) % 24, (s / 60) % 60, s % 60);
   children = malloc(service.no_processes * sizeof(pid_t));
   // service.timeout / (service.no_connections * service.no_processes);
   spacer = 1000000;
   for (i = 0; i < service.no_processes; i++) {
      pid = fork();
      if (pid < 0) {
         quit("Fork");
      } else if (pid == 0) {
         rc = start_connections(&service);
         break;
      } else {
         children[i] = pid;
      }
      usleep(spacer);
   }
   if (i != service.no_processes) {
      goto out;
   }
   for (i = 0; i < service.no_processes; i++) {
      waitpid(children[i], &rc, 0);
   }

   free(children);
 out:
   return rc;
}

void sort(uint32_t *arr, int sz)
{
   int i, j = sz - 1, k, tmp;
   if (sz == 0 || sz == 1) {
      return;
   }

   for (i = 1; i <= j; i++) {
      if (arr[i] > arr[0]) {
         tmp = arr[i];
         arr[i] = arr[j];
         arr[j] = tmp;
         i--;
         j--;
      }
   }
   tmp = arr[0];
   arr[0] = arr[j];
   arr[j] = tmp;
   j++;
   sort(arr, i-1);
   sort(arr + j, sz - j);
}

int start_connections(struct service_conf *service)
{
   /* Array of sockets to "simulate" each client */
   struct connection *auth = malloc(sizeof(struct connection) * service->no_connections);
   struct client_ctx *ctx = malloc(sizeof(struct client_ctx) * service->no_connections);
   uint32_t *offsets = malloc(sizeof(uint32_t) * service->no_connections);

   char log_name[64] = {0};
   FILE *latency_log = NULL;
   uint32_t latency = 0;
   long start_time, s, sleep_until = 0, sleep_time = 0;

   struct timeval now = {0,0};
   int rc, i, j;

   memset(auth, 0, sizeof(*auth) * service->no_connections);
   memset(ctx, 0, sizeof(*ctx) * service->no_connections);

   /* Pick a random epoch */
   gettimeofday(&now, NULL);
   srand(now.tv_usec);

   snprintf(log_name, 63, "latency.%d.log", getpid());
   latency_log = fopen(log_name, "a");

   debug("connect");
   for (i = 0; i < service->no_connections; i++) {
      if ((rc = client_connection_setup(&service->auth, &auth[i])) < 0)
         quit("Failed to setup connection");
      ctx[i].epoch = ((uint64_t)rand() << 32) | (uint64_t)rand();
   }

   /* Calculate the first round of offsets */
   for (j = 0; j < service->no_connections; j++) {
      offsets[j] = (uint32_t)(service->timeout * rand() / RAND_MAX);
   }
   sort(offsets, service->no_connections);
   gettimeofday(&now, NULL);
   sleep_until = ((now.tv_sec * 1000000 + service->timeout - 1)/service->timeout) * service->timeout;
   sleep_time = sleep_until - (now.tv_sec * 1000000 + now.tv_usec);
   if (sleep_time > 0) {
      debugf("Sleeping for %ld us", sleep_time);
      usleep(sleep_time);
   }
   gettimeofday(&now, NULL);
   start_time = (now.tv_sec * 1000000 + now.tv_usec);
   debug("Start making requests");
   for (i = 0; i < service->no_requests; i++) {
      /* Calculate the offsets */
      fprintf(latency_log, "'%d-%d': [", getpid(), i);
      for (j = 0; j < service->no_connections; j++) {
         struct timeval start, end;
         gettimeofday(&start, NULL);
         s = 1000000 * start.tv_sec + start.tv_usec;
         if (rand() % 100 < service->bench_mix) {
            if ((rc = client_reup(auth, &service->public, &service->client, ctx)) < 0) {
               error("Failed to reup request");
            }
         } else {
            if ((rc = client_login(auth, &service->public, &service->client, &service->sig, ctx)) < 0) {
               error("Failed to login request");
            }
         }
         gettimeofday(&end, NULL);
         latency = (uint32_t)((1000000 * end.tv_sec + end.tv_usec) - s);
         if (rc >= 0) {
            fprintf(latency_log, "%d,", latency);
         }

         gettimeofday(&now, NULL);
         s = 1000000 * start.tv_sec + start.tv_usec;
         sleep_time = sleep_until + offsets[j] - s;
         if (sleep_time > 0) {
            debugf("Sleeping for %ld us", sleep_time);
            usleep(sleep_time);
         }
      }
      fprintf(latency_log, "],\n");
      fflush(latency_log);

      for (j = 0; j < service->no_connections; j++) {
         offsets[j] = (uint32_t)(service->timeout * rand() / RAND_MAX);
      }
      sort(offsets, service->no_connections);
      gettimeofday(&now, NULL);
      sleep_until = ((1000000 * now.tv_sec + service->timeout - 1)/service->timeout) * service->timeout;
      sleep_time = sleep_until - (1000000 * now.tv_sec + now.tv_usec);
      if (sleep_time > 0) {
         debugf("Sleeping for %ld us", sleep_time);
         usleep(sleep_time);
      }
   }

   fclose(latency_log);

   rc = 0;
 out:
   free(auth);
   free(ctx);

   return rc;
}

const char section[][10] = {
   [ PAIR ]  = "[pair]",
   [ PUB  ]  = "[pub]",
   [ AUTH ]  = "[auth]",
   [ BENCH ] = "[bench]",
};
int read_config(FILE *file, struct service_conf *service)
{
   char *line = NULL, *end, *start;
   size_t sz = 0;
   int type = -1;
   int parsed = 0, rc;
   int i;
   struct connection auth = {0};
   if (file == NULL) {
      return 0;
   }
   while (getline(&line, &sz, file) > 0) {
      if (!strncmp(section[PAIR], line, strlen(section[PAIR]))) {
         type = PAIR;
         continue;
      } else if (!strncmp(section[PUB], line, strlen(section[PUB]))) {
         type = PUB;
         continue;
      } else if (!strncmp(section[AUTH], line, strlen(section[AUTH]))) {
         type = AUTH;
         continue;
      } else if (!strncmp(section[BENCH], line, strlen(section[BENCH]))) {
         type = BENCH;
         continue;
      }
      for (end = line; *end != '\n'; end++)
         ;
      *end = '\0';

      switch (type) {
      case PAIR:
         if (!strncmp(line, "file = ", 7)) {
            parsed |= PAIR_BIT;
            memset(service->params, 0, sizeof(service->params));
            strncpy(service->params, line + 7, sizeof(service->params) - 1);
         }
         break;
      case PUB:
         if (!strncmp(line, "file = ", 7)) {
            parsed |= PUB_BIT;
            memset(service->pubkey, 0, sizeof(service->pubkey));
            strncpy(service->pubkey, line + 7, sizeof(service->pubkey) - 1);
         }
         break;
      case AUTH:
         if (!strncmp(line, "addr = ", 7)) {
            start = end = line + 7;
            service->auth.host[0] = malloc(17 * MAX_ADDRS);
            memset(service->auth.host[0], 0, 17 * MAX_ADDRS);
            while (!('0' <= *start && *start <= '9'))
               start++;
            for (i = 0; i < MAX_ADDRS && start && end; i++) {
               end = strstr(start, " ");
               service->auth.host[i] = service->auth.host[0] + i*17;
               if (end) {
                  strncpy(service->auth.host[i], start, end - start);
                  start = end + 1;
               } else {
                  strncpy(service->auth.host[i], start, 17);
               }
            }
            service->auth.num = i;
            if (service->auth.status == CNX_UNSET) {
               service->auth.status = CNX_NORMAL;
            }
         } else if (!strncmp(line, "port = ", 7)) {
            start = line + 7;
            for (i = 0; i < MAX_ADDRS && start; i++) {
               service->auth.port[i] = (int)strtol(start, &start, 10);
            }
         } else if (!strncmp(line, "ssl = ", 6)) {
            service->auth.status = (strcmp(line + 6, "on") == 0) ? CNX_SSL : CNX_NORMAL;
         }
         break;
      case BENCH:
         if (!strncmp(line, "processes = ", 12)) {
            service->no_processes = strtol(line + 12, NULL, 10) ? : 1;
         } else if (!strncmp(line, "connections = ", 14)) {
            service->no_connections = strtol(line + 14, NULL, 10) ? : 1;
         } else if (!strncmp(line, "requests = ", 11)) {
            service->no_requests = strtol(line + 11, NULL, 10);
         } else if (!strncmp(line, "timeout = ", 10)) {
            service->timeout = 1000000 * strtol(line + 10, NULL, 10);
         } else if (!strncmp(line, "type = ", 7)) {
            if (strcmp(line + 7, "reup") == 0) {
               service->bench_mix = 100;
            } else if (strcmp(line + 7, "login") == 0) {
               service->bench_mix = 0;
            } else if (strncmp(line + 7, "mix", 3) == 0) {
               service->bench_mix = strtol(line + 10, NULL, 10);
            }
         }
         break;
      default:
         break;
      }
   }

   pairing_init(service->public.p, fopen(service->params, "r"));
   if ((rc = client_connection_setup(&service->auth, &auth)) < 0)
      quit("Failed to setup connection");
   if (strlen(service->pubkey) > 0) {
      pub_init(&service->public, fopen(service->pubkey, "r"));
   } else {
      if ((rc = client_params(&auth, &service->public, NULL)) < 0)
         quit("Failed to initialize public parameters");
   }
   if (!client_init(&service->public, &service->client, &service->sig, NULL))
      quit("Failed to initialize client");
   if ((rc = client_register(&auth, &service->public, &service->client, &service->sig)) < 0)
      quit("Failed to register");
 out:
   if (line)
      free(line);

   return parsed;
}
