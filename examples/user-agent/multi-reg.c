#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <anon-pass/debug.h>
#include "agent-util.h"

enum {PARAMS, REG, REG_IN, LOGIN, REUP, MAX_TIMER};
make_timer(full, MAX_TIMER);

struct service_conf {
   /* Connection Params */
   struct addr_conf auth;
   struct addr_conf app;
   uint64_t timeout;
   char pubkey[256];
   char clientkey[256];
};

int read_config(FILE *file, struct service_conf *service, struct public_params *public,
                struct client_secret *client, struct register_sig *sig);
int main(int argc, char *argv[]) {
   int i, rc = 0, connected = 0, parsed = 0;
   int fd;
   struct connection auth;
   struct connection app;
   char *conf = DEFAULT_CONF;
   char *client_keyfile = NULL;
   pid_t pid = 0;
   struct timeval last_reup = {0,0}, now = {0,0};
   struct service_conf service = {
      .auth = {CNX_UNSET, 0, {0}, {NULL}},
      .app = {CNX_UNSET, 0, {0}, {NULL}},
      .timeout = DEFAULT_TIMEOUT,
      .pubkey = {0},
      .clientkey = {0},
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
   pub_pp_init(&public);

   if ((rc = client_register(&auth, &public, &client, &sig)) < 0)
      quit_loc(client, "Failed to register");
   if ((rc = client_login(&auth, &public, &client, &sig, &ctx)) < 0)
      quit_loc(sig, "Failed to login");
   sleep(5);
   for (i = 0; i < 10000; i++) {
      usleep(100);
      if ((rc = client_register(&auth, &public, &client, &sig)) < 0)
         quit_loc(client, "Failed to register");
      /* if ((rc = client_login(&auth, &public, &client, &sig, &ctx)) < 0) */
      /*    quit_loc(sig, "Failed to login"); */
      /* if ((rc = client_reup(&auth, &public, &client, &ctx)) < 0) */
      /*    quit_loc(sig, "Failed to reup"); */
      if ((i + 1) % 500 == 0) {
         connection_free(&auth);
      }
   }

   rc = 0;
 out_sig:
   reg_sig_clear(&sig, 1);
 out_client:
   client_clear(&client);
   pub_clear(&public);
 out:

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
            int checked = client_init(public, client, sig, fopen(line + 7, "a+"));
            if (checked > 0)
               parsed |= KEY_BIT;
            if (checked > 1)
               parsed |= SIG_BIT;
            memset(service->clientkey, 0, sizeof(service->clientkey));
            strncpy(service->clientkey, line + 7, sizeof(service->clientkey) - 1);
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
            service->timeout = strtol(line + 10, NULL, 10);
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
            service->timeout = strtol(line + 10, NULL, 10);
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
