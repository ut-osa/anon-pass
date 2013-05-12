/*
 * Client registration, authentication, and re-up
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

#include <pbc/pbc.h>
#include <stdio.h>
#include <stdint.h>

#include <anon-pass/anon-pass.h>
#include <anon-pass/client.h>
#include <anon-pass/debug.h>

static element_t one;
static element_t G_one;
void client_init_one(struct public_params *pub)
{
   element_init_Zr(one, pub->p);
   element_set1(one);

   element_init_G1(G_one, pub->p);
   element_set1(G_one);
}

int client_init(struct public_params *pub, struct client_secret *priv,
                 struct register_sig *sig, FILE *privf)
{
   int rc = 0;
   char *line = NULL;
   size_t sz = 0;
   element_t r;

   client_init_one(pub);

   element_init_Zr(priv->d, pub->p);
   element_init_Zr(priv->r, pub->p);

   if (privf) fseek(privf, 0, SEEK_END);
   if (!privf || ftell(privf) == 0) {
      element_random(priv->d);
      element_random(priv->r);
      if (privf) {
         element_out_str(privf, INT_BASE, priv->d);
         fprintf(privf, "\n");
         element_out_str(privf, INT_BASE, priv->r);
         fprintf(privf, "\n");
      }
      rc = 1;
   } else {
      fseek(privf, 0, SEEK_SET);
      if (getline(&line, &sz, privf) > 0)
         element_set_str(priv->d, line, INT_BASE);
      else goto out;
      if (getline(&line, &sz, privf) > 0)
         element_set_str(priv->r, line, INT_BASE);
      else goto out;
      rc = 1;
      reg_sig_init(pub, sig);
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->A, line, INT_BASE);
      else goto out;
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->B, line, INT_BASE);
      else goto out;
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->ZB, line, INT_BASE);
      else goto out;
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->C, line, INT_BASE);
      else goto out;
      /* Precomputed Client Values */
      element_init_GT(sig->client.A, pub->p);
      element_init_GT(sig->client.B, pub->p);
      element_init_GT(sig->client.ZB, pub->p);
      element_init_GT(sig->client.C, pub->p);
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->client.A, line, INT_BASE);
      else goto out;
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->client.B, line, INT_BASE);
      else goto out;
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->client.ZB, line, INT_BASE);
      else goto out;
      if (getline(&line, &sz, privf) > 0)
         element_set_str(sig->client.C, line, INT_BASE);
      else goto out;
      rc = 2;
   }
   debugf("d = %B", priv->d);
   debugf("r = %B", priv->r);

 out:
   if (privf)
      fclose(privf);
   if (line)
      free(line);
   return rc;
}

void client_clear(struct client_secret *priv)
{
   element_clear(priv->d);
   element_clear(priv->r);
}

void client_clear_one()
{
   element_clear(one);
   element_clear(G_one);
}

int client_verify_pub(struct public_params *pub)
{
   int rc = 1;
   element_t lhs, rhs;
   element_init_GT(lhs, pub->p);
   element_init_GT(rhs, pub->p);

   pairing_pp_apply(lhs, pub->W, pub->pp.g);
   pairing_pp_apply(rhs, pub->Z, pub->pp.Y);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid public key");
      rc = 0;
      goto out;
   }
   element_clear(lhs);
   element_clear(rhs);
 out:
   return rc;
}

int client_create_reg_msg(struct public_params *pub, struct client_secret *client,
                          struct register_msg *msg)
{
   // Random Params: randg, randZ
   // Private Params: d, rand
   unsigned char hash[32] = {0};
   element_t c;

   element_t z1, g1;
   element_t rg, rZ;

   element_init_G1(g1, pub->p);

   element_init_Zr(z1, pub->p);
   element_init_Zr(rg, pub->p);
   element_init_Zr(rZ, pub->p);
   element_init_Zr(c, pub->p);

   reg_msg_init(pub, msg);

   element_random(rg);
   element_random(rZ);
   debugf("rand g = %B", rg);
   debugf("rand Z = %B", rZ);

   // M = (g ** d) * (Z ** r)
   element_pow_zn(msg->M, pub->g, client->d);
   element_pow_zn(g1, pub->Z, client->r);
   element_mul(msg->M, msg->M, g1);
   debugf("M = %B", msg->M);

   // R = (g ** rg) * (Z ** rZ)
   element_pow_zn(msg->R, pub->g, rg);
   element_pow_zn(g1, pub->Z, rZ);
   element_mul(msg->R, msg->R, g1);
   debugf("R = %B", msg->R);

   hash_elements(hash, (element_t *[]){&pub->g, &pub->Z, &msg->M, &msg->R, NULL});
   element_from_hash(c, hash, 32);
   debugf("c = %B", c);

   // rg = d * c + rg
   element_mul(z1, client->d, c);
   element_add(msg->rg, z1, rg);
   debugf("rg = %B", msg->rg);

   // rZ = r * c + rZ
   element_mul(z1, client->r, c);
   element_add(msg->rZ, z1, rZ);
   debugf("rZ = %B", msg->rZ);

   element_clear(g1);
   element_clear(z1);
   element_clear(rg);
   element_clear(rZ);
   element_clear(c);

   /* Send: M, R, rg, rZ */
   return 1;
}

int client_verify_reg_sig(struct public_params *pub, struct client_secret *client, struct register_sig *sig)
{
   // Input: A, B, ZB, C
   // Public: X, Y, Z
   int rc = 1;
   element_t lhs, rhs;
   element_t g1, g2;

   element_init_G1(g1, pub->p);
   element_init_G1(g2, pub->p);
   element_init_GT(lhs, pub->p);
   element_init_GT(rhs, pub->p);

   // Verify: A != 1
   if (!element_cmp(sig->A, G_one)) {
      error("A can't be one - invalid signature!");
      rc = 0;
      goto out;
   }
   // Verify: e(g, B) = e(Y, A)
   pairing_pp_apply(lhs, sig->B, pub->pp.g);
   pairing_pp_apply(rhs, sig->A, pub->pp.Y);
   /* element_pairing(lhs, pub->g, sig->B); */
   /* element_pairing(rhs, pub->Y, sig->A); */
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid signature!");
      rc = 0;
      goto out;
   }
   // Verify: e(g, ZB) = e(Z, B)
   pairing_pp_apply(lhs, sig->ZB, pub->pp.g);
   pairing_pp_apply(rhs, sig->B, pub->pp.Z);
   /* element_pairing(lhs, pub->g, sig->ZB); */
   /* element_pairing(rhs, pub->Z, sig->B); */
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid signature!");
      rc = 0;
      goto out;
   }

   // Expectation:
   // A = g ** a, B = g ** (ay), ZB = g ** (ayz),
   // C = g ** (ax + axy*(d + zr))
   //   = g ** (ax * (1 + dy + ryz))

   // e(X, A * (B ** d) * (ZB ** r))
   element_pow_zn(g1, sig->B, client->d);
   element_pow_zn(g2, sig->ZB, client->r);
   element_mul(g1, g1, g2);
   element_mul(g1, sig->A, g1);
   pairing_pp_apply(rhs, g1, pub->pp.X);
   /* element_pairing(rhs, pub->X, g1); */
   debugf("rhs = %B", rhs);

   // e(g, C)
   pairing_pp_apply(lhs, sig->C, pub->pp.g);
   /* element_pairing(lhs, sig->C, pub->g); */
   debugf("lhs = %B", lhs);

   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid signature!");
      rc = 0;
      goto out;
   }
   client_precompute_reg_sig(pub, client, sig);

 out:
   element_clear(lhs);
   element_clear(g1);
   element_clear(g2);
   element_clear(rhs);

   return rc;
}

int client_precompute_reg_sig(struct public_params *pub, struct client_secret *client, struct register_sig *sig)
{
   int rc = 1;

   element_init_GT(sig->client.A, pub->p);
   element_init_GT(sig->client.B, pub->p);
   element_init_GT(sig->client.ZB, pub->p);
   element_init_GT(sig->client.C, pub->p);

   pairing_pp_apply(sig->client.C, sig->C, pub->pp.g);
   pairing_pp_apply(sig->client.A, sig->A, pub->pp.X);
   pairing_pp_apply(sig->client.B, sig->B, pub->pp.X);
   pairing_pp_apply(sig->client.ZB, sig->ZB, pub->pp.X);

   return rc;
}

int client_save_reg_sig(struct register_sig *sig, FILE *privf)
{
   int rc = 0;
   if (!privf)
      goto out;

   debug("Starting to save signature");
   fseek(privf, 0, SEEK_END);
   element_out_str(privf, INT_BASE, sig->A);
   fprintf(privf, "\n");
   element_out_str(privf, INT_BASE, sig->B);
   fprintf(privf, "\n");
   element_out_str(privf, INT_BASE, sig->ZB);
   fprintf(privf, "\n");
   element_out_str(privf, INT_BASE, sig->C);
   fprintf(privf, "\n");

   element_out_str(privf, INT_BASE, sig->client.A);
   fprintf(privf, "\n");
   element_out_str(privf, INT_BASE, sig->client.B);
   fprintf(privf, "\n");
   element_out_str(privf, INT_BASE, sig->client.ZB);
   fprintf(privf, "\n");
   element_out_str(privf, INT_BASE, sig->client.C);
   fprintf(privf, "\n");
   rc = 1;
 out:
   return rc;
}

long client_create_login_msg(struct public_params *pub, struct client_secret *client,
                             struct register_sig *sig, struct login_msg *msg, long epoch)
{
   // Input: t, A, B, ZB, C
   // Random Params: rd, rr, rr2, b1, b2
   unsigned char hash[32] = {0};
   element_t c;

   element_t d, r, r2, b1, b2, b;
   element_t z1, gt;
   element_t vs, vx, vxy, vxyz;

   element_init_GT(gt, pub->p);
   element_init_Zr(z1, pub->p);

   element_init_Zr(d, pub->p);
   element_init_Zr(r, pub->p);
   element_init_Zr(r2, pub->p);
   element_init_Zr(b1, pub->p);
   element_init_Zr(b2, pub->p);
   element_init_Zr(b, pub->p);

   element_init_Zr(c, pub->p);
   element_init_GT(vs, pub->p);
   element_init_GT(vx, pub->p);
   element_init_GT(vxy, pub->p);
   element_init_GT(vxyz, pub->p);

   login_msg_init(pub, msg);
   if (epoch) {
      set_epoch(msg->t, epoch);
   } else {
      epoch = get_epoch(msg->t);
   }

   element_random(r);
   element_random(d);
   element_random(r2);
   element_random(b1);
   element_random(b2);
   element_mul(b, b1, b2);

   // At = sig->A ** b1
   // Bt = sig->B ** b1
   // ZBt = sig->ZB ** b1
   // Cs = sig->C ** (b1 * b2)
   element_pow_zn(msg->A, sig->A, b1);
   element_pow_zn(msg->B, sig->B, b1);
   element_pow_zn(msg->ZB, sig->ZB, b1);
   element_pow_zn(msg->C, sig->C, b);
   debugf("A = %B", msg->A);
   debugf("B = %B", msg->B);
   debugf("ZB = %B", msg->ZB);
   debugf("C = %B", msg->C);

   // vs = pair(g, Cs), vx = pair(X, At), vxy = pair(X, Bt), vxyz = pair(X, ZBt)
   element_pow_zn(vs, sig->client.C, b);
   element_pow_zn(vx, sig->client.A, b1);
   element_pow_zn(vxy, sig->client.B, b1);
   element_pow_zn(vxyz, sig->client.ZB, b1);
   debugf("vs = %B", vs);
   debugf("vx = %B", vx);
   debugf("vxy = %B", vxy);
   debugf("vxyz = %B", vxyz);

   // R1 = (vs ** rr2) * (vxy ** rd) * (vxyz ** rr)
   element_pow_zn(msg->R1, vs, r2);
   element_pow_zn(gt, vxy, d);
   element_mul(msg->R1, msg->R1, gt);
   element_pow_zn(gt, vxyz, r);
   element_mul(msg->R1, msg->R1, gt);
   debugf("R1 = %B", msg->R1);

   // Yt = gT ** (1 / (d + t))
   element_add(z1, client->d, msg->t);
   element_div(z1, one, z1);
   element_pow_zn(msg->Yt, pub->gt, z1);
   debugf("Yt = %B", msg->Yt);

   // R2 = Yt ** rd
   element_pow_zn(msg->R2, msg->Yt, d);
   debugf("R2 = %B", msg->R2);

   // c = hash(vs, vx, vxy, vxyz, R1, Yt, R2)
   hash_elements(hash, (element_t *[]){&vs, &vx, &vxy, &vxyz, &pub->gt,
            &msg->R1, &msg->Yt, &msg->R2, NULL});
   element_from_hash(c, hash, 32);
   debugf("c = %B", c);

   // rrr2 = c * (1 / b2) + rr2
   element_div(msg->r2, c, b2);
   element_add(msg->r2, msg->r2, r2);
   debugf("r2 = %B", msg->r2);
   // rrd  = -c * d + rd
   element_mul(msg->d, c, client->d);
   element_sub(msg->d, d, msg->d);
   debugf("d = %B", msg->d);
   // rrr  = -c * r + rr
   element_mul_si(msg->r, c, -1);
   element_mul(msg->r, msg->r, client->r);
   element_add(msg->r, msg->r, r);
   debugf("r = %B", msg->r);

   element_clear(b1);
   element_clear(b2);
   element_clear(b);
   element_clear(z1);
   element_clear(c);
   element_clear(d);
   element_clear(r);
   element_clear(r2);
   element_clear(gt);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);

   return epoch;
}

long client_create_reup_msg(struct public_params *pub, struct client_secret *client,
                            struct reup_msg *msg, long epoch)
{
   unsigned char hash[32];

   element_t r, c, z1, tmp;
   element_init_Zr(z1, pub->p);
   element_init_Zr(tmp, pub->p);
   element_init_Zr(r, pub->p);
   element_init_Zr(c, pub->p);
   element_random(r);

   reup_msg_init(pub, msg);
   if (epoch) {
      set_epoch(msg->t, epoch);
      epoch ++;
   } else
      epoch = get_epoch(msg->t) + 1;

   element_add(tmp, client->d, msg->t);
   element_div(z1, one, tmp);
   element_pow_zn(msg->Yt, pub->gt, z1);
   element_pow_zn(msg->Rt, msg->Yt, r);

   element_add_ui(z1, tmp, 1);
   element_div(z1, one, z1);
   element_pow_zn(msg->Ys, pub->gt, z1);
   element_pow_zn(msg->Rs, msg->Ys, r);

   // c = hash(Yt, Rt, Ys, Rs)
   hash_elements(hash, (element_t *[]){&msg->Yt, &msg->Rt, &msg->Ys, &msg->Rs, NULL});
   element_from_hash(c, hash, 32);
   debugf("c = %B", c);

   // a = -cd + r
   element_mul(msg->a, c, client->d);
   element_sub(msg->a, r, msg->a);
   debugf("a = %B", msg->a);

   element_clear(r);
   element_clear(c);
   element_clear(z1);
   element_clear(tmp);
   return epoch;
}

int client_create_multi_msg(struct public_params *pub, struct client_secret *client,
                            struct register_sig *sig, struct multi_msg *msg,
                            int no_epochs)
{
   int i;
   unsigned char hash[32] = {0};
   element_t c;

   element_t d, r, r2, b1, b2, b;
   element_t z1, gt, tmp;
   element_t vs, vx, vxy, vxyz;
   element_t **arr = malloc((no_epochs*2 + 7) * sizeof(*arr));

   element_init_GT(gt, pub->p);
   element_init_Zr(z1, pub->p);
   element_init_Zr(tmp, pub->p);

   element_init_Zr(d, pub->p);
   element_init_Zr(r, pub->p);
   element_init_Zr(r2, pub->p);
   element_init_Zr(b1, pub->p);
   element_init_Zr(b2, pub->p);
   element_init_Zr(b, pub->p);

   element_init_Zr(c, pub->p);
   element_init_GT(vs, pub->p);
   element_init_GT(vx, pub->p);
   element_init_GT(vxy, pub->p);
   element_init_GT(vxyz, pub->p);

   multi_msg_init(pub, msg, no_epochs);
   get_epoch(msg->t);

   element_random(r);
   element_random(d);
   element_random(r2);
   element_random(b1);
   element_random(b2);
   element_mul(b, b1, b2);

   element_pow_zn(msg->A, sig->A, b1);
   element_pow_zn(msg->B, sig->B, b1);
   element_pow_zn(msg->ZB, sig->ZB, b1);
   element_pow_zn(msg->C, sig->C, b);
   debugf("A = %B", msg->A);
   debugf("B = %B", msg->B);
   debugf("ZB = %B", msg->ZB);
   debugf("C = %B", msg->C);

   element_pow_zn(vs, sig->client.C, b);
   element_pow_zn(vx, sig->client.A, b1);
   element_pow_zn(vxy, sig->client.B, b1);
   element_pow_zn(vxyz, sig->client.ZB, b1);
   debugf("vs = %B", vs);
   debugf("vx = %B", vx);
   debugf("vxy = %B", vxy);
   debugf("vxyz = %B", vxyz);

   // R1 = (vs ** rr2) * (vxy ** rd) * (vxyz ** rr)
   element_pow_zn(msg->R1, vs, r2);
   element_pow_zn(gt, vxy, d);
   element_mul(msg->R1, msg->R1, gt);
   element_pow_zn(gt, vxyz, r);
   element_mul(msg->R1, msg->R1, gt);
   debugf("R1 = %B", msg->R1);

   // Yt = gT ** (1 / (d + t))
   element_add(tmp, client->d, msg->t);
   for (i = 0; i < no_epochs; i++) {
      element_div(z1, one, tmp);
      element_pow_zn(msg->Y[i], pub->gt, z1);
      debugf("Y[%d] = %B", i, msg->Y[i]);
      element_pow_zn(msg->R[i], msg->Y[i], d);
      debugf("R[%d] = %B", i, msg->R[i]);
      element_add_ui(tmp, tmp, 1);
   }

   // c = hash(vs, vx, vxy, vxyz, R1, Yt, R2)
   debug("Starting to hash");
   arr[0] = &vs;
   arr[1] = &vx;
   arr[2] = &vxy;
   arr[3] = &vxyz;
   arr[4] = &pub->gt;
   arr[5] = &msg->R1;
   for (i = 0; i < no_epochs; i++) {
      arr[6 + 2*i] = &msg->Y[i];
      arr[6 + 2*i + 1] = &msg->Y[i];
   }
   arr[6 + 2*i] = NULL;
   hash_elements(hash, arr);
   element_from_hash(c, hash, 32);
   debugf("c = %B", c);

   // rrr2 = c * (1 / b2) + rr2
   element_div(msg->r2, c, b2);
   element_add(msg->r2, msg->r2, r2);

   // rrd  = -c * d + rd
   element_mul(msg->d, c, client->d);
   element_sub(msg->d, d, msg->d);

   // rrr  = -c * r + rr
   element_mul_si(msg->r, c, -1);
   element_mul(msg->r, msg->r, client->r);
   element_add(msg->r, msg->r, r);

   element_clear(b1);
   element_clear(b2);
   element_clear(b);
   element_clear(z1);
   element_clear(tmp);
   element_clear(c);
   element_clear(d);
   element_clear(r);
   element_clear(r2);
   element_clear(gt);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);

   free(arr);

   return 1;
}
