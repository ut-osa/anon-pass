#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <anon-pass/debug.h>
#include "agent-util.h"

#define DEFAULT_MODE 0
#define LOGIN_MODE 1

enum {PARAMS, REG, REG_IN, LOGIN, REUP, MAX_TIMER};
make_timer(full, MAX_TIMER);

struct service_conf {
   /* Connection Params */
   struct addr_conf auth;
   struct addr_conf app;
   uint64_t timeout;
   int auth_mode;
   int child;
   char pubkey[256];
   char clientkey[256];
};

int read_config(FILE *file, struct service_conf *service, struct public_params *public,
                struct client_secret *client, struct register_sig *sig);
void destroy_config(struct service_conf *service);

int main(int argc, char *argv[]) {
   int i, rc = 0, parsed = 0;
   int connected = 0, retry, first_time = 1;
   long start, end, offset;
   uint64_t epoch = 0;
   int fd;
   struct connection auth = (struct connection){.sockfd = -1};
   struct connection app = (struct connection){.sockfd = -1};
   char *conf = DEFAULT_CONF;
   char *client_keyfile = NULL;
   pid_t pid = 0;
   struct timeval now = {0,0};
   struct service_conf service = {
      .auth = {CNX_UNSET, 0, {0}, {NULL}},
      .app = {CNX_UNSET, 0, {0}, {NULL}},
      .timeout = DEFAULT_TIMEOUT,
      .auth_mode = DEFAULT_MODE,
      .pubkey = {0},
      .clientkey = {0},
      .child = 0,
   };
   struct client_ctx ctx = {
      .epoch = 0,
      .len = 0,
      .key_len = 0,
      .auth_mode = 0,
      .cookies = {0},
      .key = {0},
   };
   struct public_params public;
   struct client_secret client;
   struct register_sig sig;

   /* This should all go into a configuration file */
   if (argc > 1) {
      conf = argv[1];
   }
   if (argc > 2) {
      connected = strtol(argv[2], NULL, 10);
   }
   if (argc > 3) {
      // An extra key parameter
      memset(service.clientkey, 0, sizeof(service.clientkey));
      strncpy(service.clientkey, argv[3], sizeof(service.clientkey) - 1);
   }
   parsed = read_config(fopen(conf, "r"), &service, &public, &client, &sig);
   debugf("service.clientkey: %s", service.clientkey);
   debugf("service.pubkey: %s", service.pubkey);
   for (i = 0; i < service.app.num; i++) {
      debugf("service.app: %s:%d %s", service.app.host[i], service.app.port[i],
             service.app.status == CNX_UNSET ?                          \
             "not connected" : (service.app.status == CNX_NORMAL ?      \
                                "http connection" : "ssl connection"));
   }
   for (i = 0; i < service.auth.num; i++) {
      debugf("service.auth: %s:%d %s", service.auth.host[i], service.auth.port[i],
             service.auth.status == CNX_UNSET ?                         \
             "not connected" : (service.auth.status == CNX_NORMAL ?     \
                                "http connection" : "ssl connection"));
   }
   debugf("service.timeout: %d s", service.timeout);
   ctx.auth_mode = service.auth_mode;

   if (!(parsed & PAIR_BIT))
      pairing_init(public.p, fopen(DEFAULT_PARAMS, "r"));

   if ((rc = client_connection_setup(&service.auth, &auth)) < 0)
      quit("Failed to connect");
   if ((rc = client_connection_setup(&service.app, &app)) < 0)
      quit("Failed to connect to app server");

   if (!(parsed & PUB_BIT)) {
      debug("Getting public parameters");
      if ((rc = client_params(&auth, &public, fopen(service.pubkey, "a+"))) < 0)
         quit("Failed to initialize public parameters");
   }

   if (!(parsed & KEY_BIT))
      if (client_init(&public, &client, &sig, service.clientkey != NULL ? \
                      fopen(service.clientkey,"a+") : NULL) != 2) {
         parsed &= ~(SIG_BIT);
      } else {
         parsed |= SIG_BIT;
      }

   if (!(parsed & SIG_BIT)) {
      if ((rc = client_register(&auth, &public, &client, &sig)) < 0)
         quit_loc(client, "Failed to register");
      if (client_save_reg_sig(&sig, service.clientkey != NULL ?     \
                              fopen(service.clientkey,"a+") : NULL) < 0)
         quit_loc(sig, "Failed to save signature");
   }

   retry = 0;
   while ((rc = client_login(&auth, &public, &client, &sig, &ctx)) < 0 && retry++ < 5) {
      connection_free(&auth);
      if (rc == ANON_AUTH_ERROR)
         sleep(retry + service.timeout);
      else
         sleep(retry * retry);
   }
   if (rc < 0)
      quit_loc(sig, "Failed to login");
   gettimeofday(&now, NULL);
   end = now.tv_sec * 1000000 + now.tv_usec + service.timeout;

   retry = 0;
   while ((rc = client_app_update(&app, &ctx)) < 0 && retry++ < 5) {
      connection_free(&app);
      sleep(retry * retry);
   }
   if (rc < 0)
      quit_loc(close, "Failed to update");

   /* This puts out the epoch as well, but that's compensated on gateway */
   printf("%s\n", ctx.key);

#if (!DEBUG)
   pid = fork();
   if (pid != 0) {
      if (service.child) {
         printf("%d\n", pid);
      }
      rc = 0;
      goto out_close;
   }
   fd = open("/dev/null", O_RDWR);
   dup2(fd, 0);
   dup2(fd, 1);
   dup2(fd, 2);
   close(fd);
#endif

   while (connected > 0) {
      gettimeofday(&now, NULL);
      start = now.tv_sec * 1000000 + now.tv_usec;
      offset = end - start - service.timeout/5;
      if (offset > 0) {
         offset = rand() * offset / RAND_MAX;
         usleep(offset + service.timeout/10);
      }

      gettimeofday(&now, NULL);
      debugf("%02ld:%02ld.%02ld", (now.tv_sec / 3600) % 24, (now.tv_sec / 60) % 60, now.tv_sec % 60);

      retry = 0;
      if (service.auth_mode) {
         if (first_time) {
            first_time = 0;
            goto wait;
         }
         ctx.epoch ++;
         while ((rc = client_login(&auth, &public, &client, &sig, &ctx)) < 0 && retry++ < 5) {
            connection_free(&auth);
            ctx.epoch = 0;
            sleep(retry * retry);
         }
      } else {
         while ((rc = client_reup(&auth, &public, &client, &ctx)) < 0 && retry++ < 5) {
            connection_free(&auth);
            sleep(retry);
         }
      }
      if (rc < 0)
         quit_loc(sig, "Failed to reup");

      retry = 0;
      while ((rc = client_app_update(&app, &ctx)) < 0 && retry++ < 5) {
         connection_free(&app);
         sleep(retry * retry);
      }
      if (rc < 0)
         quit_loc(close, "Failed to update");

   wait:
      connected--;
      if (!connected)
         break;

      gettimeofday(&now, NULL);
      offset = end - (1000000 * now.tv_sec + now.tv_usec);
      if (offset > 0)
         usleep(offset);
      end += service.timeout;
   }

   rc = 0;
 out_close:
   connection_free(&app);
   connection_free(&auth);
 out_sig:
   destroy_client(&ctx);
   reg_sig_clear(&sig, 1);
 out_client:
   client_clear_one();
   client_clear(&client);
   pub_clear(&public);
 out:
   destroy_config(&service);

   return rc;
}

const char section[][10] = {
   [ PAIR ] = "[pair]",
   [ KEY  ] = "[key]",
   [ PUB  ] = "[pub]",
   [ AUTH ] = "[auth]",
   [ APP ]  = "[app]",
};
int read_config(FILE *file, struct service_conf *service, struct public_params *public,
                struct client_secret *client, struct register_sig *sig)
{
   char *line = NULL, *end, *start;
   size_t sz = 0;
   int type = -1;
   int parsed = 0;
   int i;
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
      } else if (!strncmp(section[KEY], line, strlen(section[KEY]))) {
         type = KEY;
         continue;
      } else if (!strncmp(section[AUTH], line, strlen(section[AUTH]))) {
         type = AUTH;
         continue;
      } else if (!strncmp(section[APP], line, strlen(section[APP]))) {
         type = APP;
         continue;
      }
      for (end = line; *end != '\n'; end++)
         ;
      *end = '\0';

      switch (type) {
      case PAIR:
         if (!strncmp(line, "file = ", 7)) {
            pairing_init(public->p, fopen(line + 7, "r"));
            parsed |= PAIR_BIT;
         }
         break;
      case PUB:
         if (!strncmp(line, "file = ", 7)) {
            parsed |= pub_init(public, fopen(line + 7, "r")) ? PUB_BIT : 0;
            memset(service->pubkey, 0, sizeof(service->pubkey));
            strncpy(service->pubkey, line + 7, sizeof(service->pubkey) - 1);
         }
         break;
      case KEY:
         if (!strncmp(line, "file = ", 7)) {
            int checked = 0;
            char tmp[256] = {0};
            if (strlen(line + 7) == 0) {
               memset(service->clientkey, 0, sizeof(service->clientkey));
               break;
            }
            strcpy(tmp, service->clientkey);
            memset(service->clientkey, 0, sizeof(service->clientkey));
            strcat(service->clientkey, line + 7);
            strcat(service->clientkey, tmp);
            checked = client_init(public, client, sig, fopen(service->clientkey, "a+"));
            if (checked > 0)
               parsed |= KEY_BIT;
            if (checked > 1)
               parsed |= SIG_BIT;
         }
         break;
      case AUTH:
         if (!strncmp(line, "addr = ", 7)) {
            start = end = line + 7;
            service->auth.host[0] = malloc(17 * MAX_ADDRS);
            memset(service->auth.host[0], 0, 17 * MAX_ADDRS);
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
            for (i = 0; i < 4 && start; i++) {
               service->auth.port[i] = (int)strtol(start, &start, 10);
            }
         } else if (!strncmp(line, "ssl = ", 6)) {
            service->auth.status = (strcmp(line + 6, "on") == 0) ? CNX_SSL : CNX_NORMAL;
         } else if (!strncmp(line, "timeout = ", 10)) {
            service->timeout = 1000000 * strtol(line + 10, NULL, 10);
         } else if (!strncmp(line, "auth_mode = ", 12)) {
            service->auth_mode = strtol(line + 12, NULL, 10);
         }
         break;
      case APP:
         if (!strncmp(line, "addr = ", 7)) {
            start = end = line + 7;
            service->app.host[0] = malloc(17 * MAX_ADDRS);
            memset(service->app.host[0], 0, 17 * MAX_ADDRS);
            for (i = 0; i < MAX_ADDRS && start && end; i++) {
               end = strstr(start, " ");
               service->app.host[i] = service->app.host[0] + i*17;
               if (end) {
                  strncpy(service->app.host[i], start, end - start);
                  start = end + 1;
               } else {
                  strncpy(service->app.host[i], start, 17);
               }
            }
            service->app.num = i;
            if (service->app.status == CNX_UNSET) {
               service->app.status = CNX_NORMAL;
            }
         } else if (!strncmp(line, "port = ", 7)) {
            start = line + 7;
            for (i = 0; i < 4 && start; i++) {
               service->app.port[i] = (int)strtol(start, &start, 10);
            }
         } else if (!strncmp(line, "ssl = ", 6)) {
            service->app.status = (strcmp(line + 6, "on") == 0) ? CNX_SSL : CNX_NORMAL;
         } else if (!strncmp(line, "timeout = ", 10)) {
            service->timeout = 1000000 * strtol(line + 10, NULL, 10);
         } else if (!strncmp(line, "child = ", 8)) {
            service->child = strtol(line + 8, NULL, 10);
         }
         break;
      default:
         break;
      }
   }
   if (line)
      free(line);
   return parsed;
}

void destroy_config(struct service_conf *config)
{
   if (config->auth.host[0]) {
      free(config->auth.host[0]);
   }
   if (config->app.host[0]) {
      free(config->app.host[0]);
   }
}
