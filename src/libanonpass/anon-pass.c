/*
 * Server registration, authentication, and re-up
 *
 * 1: Jan Camenisch and Anna Lysyanskaya. Signature Schemes and
 *    Anonymous Credentials from Bilinear Maps. CRYPTO, 2004.
 *
 * 2: Jan Camenisch et al. How to Win the Clone Wars: Efficient
 *     Periodic n-Time Anonymous Authentication
 */
#ifndef DEBUG
#define DEBUG 0
#endif
#ifndef BENCHMARK
#define BENCHMARK 0
#endif
#if (DEBUG)
#define PBC_DEBUG
#endif

#ifdef USE_OPENSSL
#else
#include <polarssl/sha1.h>
#endif
#include <pbc/pbc.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include <anon-pass/anon-pass.h>
#include <anon-pass/debug.h>

void pairing_init(pairing_t p, FILE *f)
{
   size_t count = 0;
   char s[4*4096];

   if (!f) {
      error("No file");
      exit(-1);
   }

   count = fread(s, 1, 16384, f);
   fclose(f);
   if (!count) {
      error("Could not read pairing initialization");
      exit(-1);
   }

   if (pairing_init_set_buf(p, s, count)) {
      error("Could not initialize pairing");
   }
}

int pub_init(struct public_params *pub, FILE *pubf)
{
   char *line = NULL;
   size_t sz = 0;
   int rc = 0;

   element_init_G1(pub->g, pub->p);
   element_init_G1(pub->X, pub->p);
   element_init_G1(pub->Y, pub->p);
   element_init_G1(pub->Z, pub->p);
   element_init_G1(pub->W, pub->p);
   element_init_GT(pub->gt, pub->p);

   if (pubf && fseek(pubf, 0, SEEK_END) == 0 && ftell(pubf) != 0) {
      fseek(pubf, 0, SEEK_SET);
      if (getline(&line, &sz, pubf) > 0)
         element_set_str(pub->g, line, ELE_BASE);
      else goto out;
      if (getline(&line, &sz, pubf) > 0)
         element_set_str(pub->X, line, ELE_BASE);
      else goto out;
      if (getline(&line, &sz, pubf) > 0)
         element_set_str(pub->Y, line, ELE_BASE);
      else goto out;
      if (getline(&line, &sz, pubf) > 0)
         element_set_str(pub->Z, line, ELE_BASE);
      else goto out;
      /* This is never saved to a file */
      pub_pp_init(pub);
      rc = 1;
   }
 out:
   if (pubf)
      fclose(pubf);
   if (line)
      free(line);
   return rc;
}

int pub_pp_init(struct public_params *pub)
{
      pairing_pp_init(pub->pp.g, pub->g, pub->p);
      pairing_pp_init(pub->pp.X, pub->X, pub->p);
      pairing_pp_init(pub->pp.Y, pub->Y, pub->p);
      pairing_pp_init(pub->pp.Z, pub->Z, pub->p);
      pairing_pp_apply(pub->gt, pub->g, pub->pp.g);
}

void reg_msg_init(struct public_params *pub, struct register_msg *msg)
{
   element_init_G1(msg->M, pub->p);
   element_init_G1(msg->R, pub->p);
   element_init_Zr(msg->rg, pub->p);
   element_init_Zr(msg->rZ, pub->p);
}

void reg_sig_init(struct public_params *pub, struct register_sig *sig)
{
   element_init_G1(sig->A, pub->p);
   element_init_G1(sig->B, pub->p);
   element_init_G1(sig->ZB, pub->p);
   element_init_G1(sig->C, pub->p);
}

void login_msg_init(struct public_params *pub, struct login_msg *msg)
{
   element_init_G1(msg->A, pub->p);
   element_init_G1(msg->B, pub->p);
   element_init_G1(msg->ZB, pub->p);
   element_init_G1(msg->C, pub->p);

   element_init_Zr(msg->d, pub->p);
   element_init_Zr(msg->r, pub->p);
   element_init_Zr(msg->r2, pub->p);

   element_init_GT(msg->R1, pub->p);
   element_init_GT(msg->R2, pub->p);
   element_init_GT(msg->Yt, pub->p);
   element_init_Zr(msg->t,  pub->p);
}

void reup_msg_init(struct public_params *pub, struct reup_msg *msg)
{
   element_init_Zr(msg->a,  pub->p);
   element_init_GT(msg->Yt, pub->p);
   element_init_GT(msg->Rt, pub->p);
   element_init_GT(msg->Ys, pub->p);
   element_init_GT(msg->Rs, pub->p);
   element_init_Zr(msg->t,  pub->p);
}

void multi_msg_init(struct public_params *pub, struct multi_msg *msg, int epochs)
{
   element_init_G1(msg->A, pub->p);
   element_init_G1(msg->B, pub->p);
   element_init_G1(msg->ZB, pub->p);
   element_init_G1(msg->C, pub->p);

   element_init_Zr(msg->d, pub->p);
   element_init_Zr(msg->r, pub->p);
   element_init_Zr(msg->r2, pub->p);

   element_init_GT(msg->R1, pub->p);
   element_init_Zr(msg->t,  pub->p);
   msg->epochs = epochs;
   msg->R = malloc(epochs * sizeof(*msg->R));
   msg->Y = malloc(epochs * sizeof(*msg->Y));
   for (epochs--; epochs >= 0; epochs --) {
      element_init_GT(msg->R[epochs], pub->p);
      element_init_GT(msg->Y[epochs], pub->p);
   }
}

void pub_clear(struct public_params *pub)
{
   pairing_pp_clear(pub->pp.g);
   pairing_pp_clear(pub->pp.X);
   pairing_pp_clear(pub->pp.Y);
   pairing_pp_clear(pub->pp.Z);

   element_clear(pub->g);
   element_clear(pub->X);
   element_clear(pub->Y);
   element_clear(pub->Z);
   element_clear(pub->W);
   element_clear(pub->gt);
   pairing_clear(pub->p);
}

void reg_msg_clear(struct register_msg *msg)
{
   element_clear(msg->M);
   element_clear(msg->R);
   element_clear(msg->rg);
   element_clear(msg->rZ);
}

void reg_sig_clear(struct register_sig *sig, int isclient)
{
   element_clear(sig->A);
   element_clear(sig->B);
   element_clear(sig->ZB);
   element_clear(sig->C);

   if (isclient) {
      element_clear(sig->client.A);
      element_clear(sig->client.B);
      element_clear(sig->client.ZB);
      element_clear(sig->client.C);
   }
}

void login_msg_clear(struct login_msg *msg)
{
   element_clear(msg->A);
   element_clear(msg->B);
   element_clear(msg->ZB);
   element_clear(msg->C);

   element_clear(msg->d);
   element_clear(msg->r);
   element_clear(msg->r2);

   element_clear(msg->R1);
   element_clear(msg->Yt);
   element_clear(msg->R2);
   element_clear(msg->t);
}

void reup_msg_clear(struct reup_msg *msg)
{
   element_clear(msg->a);
   element_clear(msg->Yt);
   element_clear(msg->Rt);
   element_clear(msg->Ys);
   element_clear(msg->Rs);
   element_clear(msg->t);
}

void multi_msg_clear(struct multi_msg *msg)
{
   element_clear(msg->A);
   element_clear(msg->B);
   element_clear(msg->ZB);
   element_clear(msg->C);

   element_clear(msg->d);
   element_clear(msg->r);
   element_clear(msg->r2);

   element_clear(msg->R1);
   element_clear(msg->t);
   for (msg->epochs --; msg->epochs >= 0; msg->epochs--) {
      element_clear(msg->Y[msg->epochs]);
      element_clear(msg->R[msg->epochs]);
   }
   free(msg->Y);
   free(msg->R);
}

void hash_element(unsigned char *hash, element_t el)
{
   unsigned char data[128];
   size_t len = element_length_in_bytes(el);
   element_to_bytes(data, el);
   sha1(data, len, hash);
}

void hash_elements(unsigned char *hash, element_t *els[])
{
   int i;
   size_t len, sz = 0;
   unsigned char *data = NULL;
   sha1_context ctx;
   sha1_starts(&ctx);

   for (i = 0; *els[i]; i++) {
      len = element_length_in_bytes(*els[i]);
      if (len > sz && (sz = len))
         data = realloc(data, sz);
      element_to_bytes(data, *els[i]);
      sha1_update(&ctx, data, len);
   }
   sha1_finish(&ctx, hash);
   if (data)
      free(data);
}

static long _epoch_offset = 0;
long set_offset(long o)
{
   _epoch_offset = o;
   return o;
}

long get_epoch(element_t t)
{
   long epoch;
   epoch = (time(NULL) + _epoch_offset) / (TIME_PERIOD);
   if ((void *)t != NULL)
      element_set_si(t, epoch);
   return epoch;
}

long get_fuzzy_epoch(element_t t, element_t t2)
{
   long curr = time(NULL) + _epoch_offset;
   long epoch = curr / (TIME_PERIOD);
   element_set_si(t, epoch - 1);
   element_set_si(t2, epoch + 1);
   return epoch;
}

void set_epoch(element_t t, long epoch)
{
   element_set_si(t, epoch);
}
