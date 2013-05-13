/*
 * Basic implementation of the pairing-based CL blind signature [1]
 *
 * 1: Jan Camenisch and Anna Lysyanskaya. Signature Schemes and
 *    Anonymous Credentials from Bilinear Maps. CRYPTO, 2004.
 */
#ifndef DEBUG
#define DEBUG 0
#endif

#include <stdio.h>
#if (DEBUG)
#define PBC_DEBUG
#endif
#include <pbc/pbc.h>

#include <sys/time.h>
#include <stdint.h>

#include <anon-pass/debug.h>
#include <anon-pass/server.h>
#include <anon-pass/client.h>
#include <anon-pass/anon-pass.h>

#define DEFAULT_PARAMS "param/a.param"
#if (DEBUG)
#define N_ITERS 1
#else
#define N_ITERS 100
#endif

extern long client_create_login_msg_base(struct public_params *pub,
                                      struct client_secret *client,
                                         struct register_sig *sig, struct login_msg *msg);
long client_create_login_msg_pp(struct public_params *pub,
                                      struct client_secret *client,
                                struct register_sig *sig, struct login_msg *msg);
long client_create_login_msg_sig(struct public_params *pub,
                                      struct client_secret *client,
                                 struct register_sig *sig, struct login_msg *msg);
int server_verify_login_msg_base(struct public_params *pub, struct server_secret *server, struct login_msg *msg);
int server_verify_login_msg_pp(struct public_params *pub, struct server_secret *server, struct login_msg *msg);
int server_verify_login_msg_sig(struct public_params *pub, struct server_secret *server, struct login_msg *msg);

long client_create_multi_msg_opt(struct public_params *pub, struct client_secret *client,
                                 struct register_sig *sig, struct multi_msg *msg,
                                 int no_epochs);
long server_verify_multi_msg_opt(struct public_params *pub, struct server_secret *server, struct multi_msg *msg);

#define MULTI 2
#define EPOCHS (MULTI+1)

struct wire_msg
{
   uint8_t buf[2048];
};

int main(int argc, char *argv[])
{
   int ret = 0, i, j, len;
   struct public_params pub, cpub;
   struct server_secret server;
   struct client_secret client;
   struct register_msg client_msg[N_ITERS];
   struct register_sig client_sig[N_ITERS];
   struct login_msg client_login[N_ITERS];
   struct reup_msg client_reup[N_ITERS * MULTI];
   struct multi_msg client_multi[N_ITERS];
   struct register_msg server_msg[N_ITERS];
   struct register_sig server_sig[N_ITERS];
   struct login_msg server_login[N_ITERS];
   struct reup_msg server_reup[N_ITERS * MULTI];
   struct multi_msg server_multi[N_ITERS];
   struct wire_msg wire[N_ITERS * MULTI];

   struct timeval start = {0}, end = {0};
   unsigned long time;
   /*
    * Usage: arg1 = param, arg2 = public key, arg3 = server key, arg4 = client key
    */

   pairing_init(pub.p, (argc > 1 ? fopen(argv[1], "r") : fopen(DEFAULT_PARAMS, "r")));
   pairing_init(cpub.p, (argc > 1 ? fopen(argv[1], "r") : fopen(DEFAULT_PARAMS, "r")));

   debug("Starting");

   /* Read in and initialize the public and private parameters */
   debug("Setup(n)");

   // Public Params: q, G1 == G2, Gt, g1, g2, gt, X, Y, Z, [W = Y ** z]
   // Private Params: x, y, z

   // Should pass in a file
   debug("Initializing server");
   server_init(&pub, &server, argc > 2 ? fopen(argv[2], "a+") : NULL,
                  argc > 3 ? fopen(argv[3], "a+") : NULL);
   debug("Initializing client");
   pub_init(&cpub, argc > 2 ? fopen(argv[2], "a+") : NULL);
   client_init(&cpub, &client, client_sig, argc > 4 ? fopen(argv[4], "a+") : NULL);
   if (argc <= 2) {
      size_t len = 0;
      uint8_t buf[128] = {0};
      len += element_to_bytes(buf, pub.g);
      element_from_bytes(cpub.g, buf);
      len += element_to_bytes(buf, pub.X);
      element_from_bytes(cpub.X, buf);
      len += element_to_bytes(buf, pub.Y);
      element_from_bytes(cpub.Y, buf);
      len += element_to_bytes(buf, pub.Z);
      element_from_bytes(cpub.Z, buf);
      len += element_to_bytes(buf, pub.W);
      element_from_bytes(cpub.W, buf);
      /* printf("Pub Len %ld\n", len); */
   }
   pub_pp_init(&cpub);
   if (!client_verify_pub(&cpub))
      goto out;

   init_one(&cpub);

   debug("Registration start");

   /* Client Operation */
   gettimeofday(&start, NULL);

   time_code(client, reg, N_ITERS,
           client_create_reg_msg(&cpub, &client, client_msg + i);
        );

   time_code(client, wire, N_ITERS,
           size_t sz = 0;
           sz += element_to_bytes(wire[i].buf + sz, client_msg[i].M);
           sz += element_to_bytes(wire[i].buf + sz, client_msg[i].R);
           sz += element_to_bytes(wire[i].buf + sz, client_msg[i].rg);
           sz += element_to_bytes(wire[i].buf + sz, client_msg[i].rZ);
           debugf("Wire size: %d", sz);
        );

   time_code(server, wire, N_ITERS,
           size_t sz = 0;
           reg_msg_init(&pub, server_msg + i);
           sz += element_from_bytes(server_msg[i].M, wire[i].buf + sz);
           sz += element_from_bytes(server_msg[i].R, wire[i].buf + sz);
           sz += element_from_bytes(server_msg[i].rg, wire[i].buf + sz);
           sz += element_from_bytes(server_msg[i].rZ, wire[i].buf + sz);
        );

   time_code(server, verify, N_ITERS,
           if (!(ret = server_verify_reg_msg(&pub, &server, server_msg + i))) {
              error("Server failed to verify client message");
              goto out;
           }
        );

   time_code(server, sign, N_ITERS,
             server_sign_reg_msg(&pub, &server, server_msg + i, server_sig + i);
        );

   time_code(server, wire, N_ITERS,
           size_t sz = 0;
           sz += element_to_bytes(wire[i].buf + sz, server_sig[i].A);
           sz += element_to_bytes(wire[i].buf + sz, server_sig[i].B);
           sz += element_to_bytes(wire[i].buf + sz, server_sig[i].ZB);
           sz += element_to_bytes(wire[i].buf + sz, server_sig[i].C);
           debugf("Wire size: %d", sz);
        );

   time_code(client, wire, N_ITERS,
           size_t sz = 0;
           reg_sig_init(&cpub, client_sig + i);
           sz += element_from_bytes(client_sig[i].A, wire[i].buf + sz);
           sz += element_from_bytes(client_sig[i].B, wire[i].buf + sz);
           sz += element_from_bytes(client_sig[i].ZB, wire[i].buf + sz);
           sz += element_from_bytes(client_sig[i].C, wire[i].buf + sz);
        );

   time_code(client, verify, N_ITERS,
           if (!(ret = client_verify_reg_sig(&cpub, &client, client_sig + i))) {
              error("Server failed to verify server signature");
              goto out;
           }
        );

   gettimeofday(&end, NULL);
   time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
   outputf("register\t%ld.%06ld s", time / 1000000, time % 1000000);
   outputf("\t-> %ld.%03ld ms", (time / N_ITERS) / 1000, (time / N_ITERS) % 1000);

#if 0
   // Login
   gettimeofday(&start, NULL);
   time_code(client, login-base, N_ITERS,
           client_create_login_msg_base(&cpub, &client,
                                   client_sig + i, client_login + i);
        );

   time_code(client, login-pp, N_ITERS,
           client_create_login_msg_pp(&cpub, &client,
                                   client_sig + i, client_login + i);
        );


   time_code(client, login-sig, N_ITERS,
           client_create_login_msg_sig(&cpub, &client,
                                   client_sig + i, client_login + i);
        );

   time_code(client, wire, N_ITERS,
           size_t sz = 0;
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].A);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].B);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].ZB);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].C);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].d);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].r);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].r2);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].R1);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].Yt);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].R2);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].t);
           debugf("Wire size: %d", sz);
        );

   time_code(server, wire, N_ITERS,
           size_t sz = 0;
           login_msg_init(&pub, server_login + i);
           sz += element_from_bytes(server_login[i].A,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].B,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].ZB, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].C,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].d,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].r,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].r2, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].R1, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].Yt, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].R2, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].t,  wire[i].buf + sz);
        );

   time_code(server, verify-base, N_ITERS,
           if (!(ret = server_verify_login_msg_base(&pub, &server, server_login + i))) {
              error("Server failed to verify client message");
              goto out;
           }
        );

   time_code(server, verify-pp, N_ITERS,
           if (!(ret = server_verify_login_msg_pp(&pub, &server, server_login + i))) {
              error("Server failed to verify client message");
              goto out;
           }
        );

   time_code(server, verify-sig, N_ITERS,
           if (!(ret = server_verify_login_msg_sig(&pub, &server, server_login + i))) {
              error("Server failed to verify client message");
              goto out;
           }
        );

   gettimeofday(&end, NULL);
   time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
   outputf("login\t%ld.%06ld s", time / 1000000, time % 1000000);
   outputf("\t-> %ld.%03ld ms", (time / N_ITERS) / 1000, (time / N_ITERS) % 1000);

   // Reup
   gettimeofday(&start, NULL);
   time_code(client, reup, N_ITERS,
           client_create_reup_msg(&cpub, &client, client_reup + i, 0);
        );

   time_code(client, wire, N_ITERS,
           size_t sz = 0;
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Yt);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Rt);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Ys);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Rs);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].a);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].t);
           debugf("Wire size: %d", sz);
        );

   time_code(server, wire, N_ITERS,
           size_t sz = 0;
           reup_msg_init(&pub, server_reup + i);
           sz += element_from_bytes(server_reup[i].Yt, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].Rt, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].Ys, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].Rs, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].a,  wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].t,  wire[i].buf + sz);
        );

   time_code(server, verify, N_ITERS,
           server_verify_reup_msg(&pub, server_reup + i);
        );

   gettimeofday(&end, NULL);
   time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
   outputf("reup\t%ld.%06ld s", time / 1000000, time % 1000000);
   outputf("\t-> %ld.%03ld ms", (time / N_ITERS) / 1000, (time / N_ITERS) % 1000);
#endif

   // Multi
   gettimeofday(&start, NULL);
   long some_count = 0;
   time_code(client, multi, N_ITERS,
             some_count += client_create_multi_msg_naive(&cpub, &client,
                                                         client_sig + i, client_login + i,
                                                         client_reup + MULTI*i, EPOCHS);
        );
   printf("client multi-naive only reup time: %ld %ld\n",
          some_count, some_count / N_ITERS);


   some_count = 0;
   time_code(client, multi, N_ITERS,
             some_count += client_create_multi_msg_opt(&cpub, &client, client_sig + i, client_multi + i, EPOCHS);
        );
   printf("client multi-opt only reup time: %ld %ld\n",
          some_count, some_count / N_ITERS);

   time_code(client, wire, N_ITERS,
           size_t sz = 0;
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].A);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].B);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].ZB);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].C);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].d);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].r);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].r2);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].R1);
           sz += element_to_bytes(wire[i].buf + sz, client_multi[i].t);
           for (j = 0; j < client_multi[i].epochs; j++) {
              sz += element_to_bytes(wire[i].buf + sz, client_multi[i].Y[j]);
              sz += element_to_bytes(wire[i].buf + sz, client_multi[i].R[j]);
           }
           len = sz;
           debugf("Multi_Wire size: %d", sz);
        );

   time_code(server, wire, N_ITERS,
           size_t sz = 0;
           multi_msg_init(&pub, server_multi + i, EPOCHS);
           sz += element_from_bytes(server_multi[i].A,  wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].B,  wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].ZB, wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].C,  wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].d,  wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].r,  wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].r2, wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].R1, wire[i].buf + sz);
           sz += element_from_bytes(server_multi[i].t,  wire[i].buf + sz);
           for (j = 0; sz < len; j++) {
              sz += element_from_bytes(server_multi[i].Y[j], wire[i].buf + sz);
              sz += element_from_bytes(server_multi[i].R[j], wire[i].buf + sz);
           }
        );

   time_code(client, wire, N_ITERS,
           size_t sz = 0;
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].A);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].B);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].ZB);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].C);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].d);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].r);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].r2);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].R1);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].Yt);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].R2);
           sz += element_to_bytes(wire[i].buf + sz, client_login[i].t);
           debugf("Wire size: %d", sz);
        );

   time_code(server, wire, N_ITERS,
           size_t sz = 0;
           login_msg_init(&pub, server_login + i);
           sz += element_from_bytes(server_login[i].A,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].B,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].ZB, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].C,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].d,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].r,  wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].r2, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].R1, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].Yt, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].R2, wire[i].buf + sz);
           sz += element_from_bytes(server_login[i].t,  wire[i].buf + sz);
        );

   time_code(client, wire, MULTI*N_ITERS,
           size_t sz = 0;
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Yt);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Rt);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Ys);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].Rs);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].a);
           sz += element_to_bytes(wire[i].buf + sz, client_reup[i].t);
           debugf("Wire size: %d", sz);
        );

   time_code(server, wire, MULTI*N_ITERS,
           size_t sz = 0;
           reup_msg_init(&pub, server_reup + i);
           sz += element_from_bytes(server_reup[i].Yt, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].Rt, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].Ys, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].Rs, wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].a,  wire[i].buf + sz);
           sz += element_from_bytes(server_reup[i].t,  wire[i].buf + sz);
        );

   some_count = 0;
   time_code(server, verify-opt, N_ITERS,
             some_count += server_verify_multi_msg_opt(&pub, &server, server_multi + i);
        );
   printf("server multi-opt only reup time: %ld %ld\n",
          some_count, some_count / N_ITERS);

   some_count = 0;
   time_code(server, verify-opt, N_ITERS,
             some_count += server_verify_multi_msg_naive(&pub, &server,
                                                         server_login + i,
                                                         server_reup + MULTI*i, EPOCHS);
        );
   printf("server multi-naive only reup time: %ld %ld\n",
          some_count, some_count / N_ITERS);

   gettimeofday(&end, NULL);
   time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
   outputf("multi\t%ld.%06ld s", time / 1000000, time % 1000000);
   outputf("\t-> %ld.%03ld ms", (time / N_ITERS) / 1000, (time / N_ITERS) % 1000);

 out:
   for (i = 0; i < N_ITERS; i++) {
#if 0
      reg_sig_clear(client_sig + i, 1);
      reg_msg_clear(client_msg + i);
      login_msg_clear(client_login + i);
      reup_msg_clear(client_reup + i);
      reg_sig_clear(server_sig + i, 0);
      reg_msg_clear(server_msg + i);
      login_msg_clear(server_login + i);
      reup_msg_clear(server_reup + i);
#endif
      multi_msg_clear(server_multi + i);
      multi_msg_clear(client_multi + i);
   }
   client_clear(&client);
   server_clear(&server);
   pub_clear(&pub);
   pub_clear(&cpub);

   return ret;
}
