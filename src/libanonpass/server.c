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

#include <pbc/pbc.h>
#include <stdio.h>
#include <stdint.h>

#include <anon-pass/anon-pass.h>
#include <anon-pass/server.h>
#include <anon-pass/debug.h>

static element_t G_one;
void server_init(struct public_params *pub, struct server_secret *priv,
                 FILE *pubf, FILE * privf)
{
   char *line = NULL;
   size_t sz = 0;
   element_t w;

   element_init_Zr(priv->x, pub->p);
   element_init_Zr(priv->y, pub->p);
   element_init_Zr(priv->z, pub->p);
   element_init_Zr(w, pub->p);

   element_init_G1(pub->g, pub->p);
   element_init_G1(pub->X, pub->p);
   element_init_G1(pub->Y, pub->p);
   element_init_G1(pub->Z, pub->p);
   element_init_G1(pub->W, pub->p);

   element_init_GT(pub->gt, pub->p);

   element_init_G1(G_one, pub->p);
   element_set1(G_one);

   if (privf) fseek(privf, 0, SEEK_END);
   if (!privf || ftell(privf) == 0) {
      debug("Initializing new values");
      element_random(priv->x);
      element_random(priv->y);
      element_random(priv->z);
      element_mul(w, priv->y, priv->z);
      if (privf) {
         element_out_str(privf, INT_BASE, priv->x);
         fprintf(privf, "\n");
         element_out_str(privf, INT_BASE, priv->y);
         fprintf(privf, "\n");
         element_out_str(privf, INT_BASE, priv->z);
         fprintf(privf, "\n");
         element_out_str(privf, INT_BASE, w);
         fprintf(privf, "\n");
      }
   } else {
      debug("Using the old values");
      fseek(privf, 0, SEEK_SET);
      if (getline(&line, &sz, privf) > 0)
         element_set_str(priv->x, line, INT_BASE);
      else
         error("Could not read line\n");
      if (getline(&line, &sz, privf) > 0)
         element_set_str(priv->y, line, INT_BASE);
      else
         error("Could not read line\n");
      if (getline(&line, &sz, privf) > 0)
         element_set_str(priv->z, line, INT_BASE);
      else
         error("Could not read line\n");
      if (getline(&line, &sz, privf) > 0)
         element_set_str(w, line, INT_BASE);
      else
         error("Could not read line\n");
   }
   debugf("x = %B", priv->x);
   debugf("y = %B", priv->y);
   debugf("z = %B", priv->z);

   if (pubf) fseek(pubf, 0, SEEK_END);
   if (!pubf || ftell(pubf) == 0) {
      // Generate new, random elements
      element_random(pub->g);
      element_pow_zn(pub->X, pub->g, priv->x);
      element_pow_zn(pub->Y, pub->g, priv->y);
      element_pow_zn(pub->Z, pub->g, priv->z);
      element_pow_zn(pub->W, pub->g, w);
      if (pubf) {
         element_out_str(pubf, ELE_BASE, pub->g);
         fprintf(pubf, "\n");
         element_out_str(pubf, ELE_BASE, pub->X);
         fprintf(pubf, "\n");
         element_out_str(pubf, ELE_BASE, pub->Y);
         fprintf(pubf, "\n");
         element_out_str(pubf, ELE_BASE, pub->Z);
         fprintf(pubf, "\n");
         element_out_str(pubf, ELE_BASE, pub->W);
         fprintf(pubf, "\n");
      }
   } else {
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
      if (getline(&line, &sz, pubf) > 0)
         element_set_str(pub->W, line, ELE_BASE);
      else goto out;
   }
   // Do the preprocessing
   pub_pp_init(pub);
   debugf("g = %B", pub->g);
   debugf("X = %B", pub->X);
   debugf("Y = %B", pub->Y);
   debugf("Z = %B", pub->Z);
   debugf("W = %B", pub->W);
   debugf("e(g,g) = %B", pub->gt);

 out:
   element_clear(w);
   if (line)
      free(line);
   if (pubf)
      fclose(pubf);
   if (privf)
      fclose(privf);
}

void server_clear(struct server_secret *priv)
{
   element_clear(priv->x);
   element_clear(priv->y);
   element_clear(priv->z);
}

/*
 * Server Operation
 * Input: M, R, rg, rZ
 */
int server_verify_reg_msg(struct public_params *pub, struct server_secret *server, struct register_msg *msg)
{
   int rc = 1;
   element_t lhs, rhs;
   element_t g1;
   element_t c;
   unsigned char hash[32];

   element_init_G1(g1, pub->p);
   element_init_G1(lhs, pub->p);
   element_init_G1(rhs, pub->p);
   element_init_Zr(c, pub->p);

   hash_elements(hash, (element_t *[]){&pub->g, &pub->Z, &msg->M, &msg->R, NULL});
   element_from_hash(c, hash, 32);
   debugf("c = %B", c);

   // assert (M ** c) * R == (g ** rg) * (Z ** rZ)
   element_pow_zn(lhs, msg->M, c);
   element_mul(lhs, lhs, msg->R);
   debugf("lhs = %B", lhs);

   element_pow_zn(g1, pub->g, msg->rg);
   element_pow_zn(rhs, pub->Z, msg->rZ);
   element_mul(rhs, g1, rhs);
   debugf("rhs = %B", rhs);

   if (element_cmp(lhs, rhs)) {
      error("left and right don't match");
      rc = 0;
      goto out;
   }

 out:
   element_clear(c);
   element_clear(g1);
   element_clear(lhs);
   element_clear(rhs);

   return rc;
}

int server_sign_reg_msg(struct public_params *pub, struct server_secret *server, struct register_msg *msg, struct register_sig *sig)
{
   element_t g1;
   element_t a, z1;

   reg_sig_init(pub, sig);

   element_init_G1(g1, pub->p);
   element_init_Zr(a, pub->p);
   element_init_Zr(z1, pub->p);

   // sign:
   // Random Param: a
   element_random(a);

   // A = g ** a, B = A ** y, ZB = A ** (y * z)
   element_pow_zn(sig->A, pub->g, a);
   element_pow_zn(sig->B, sig->A, server->y);
   element_pow_zn(sig->ZB, sig->B, server->z);

   // C = (A ** x) * (M ** (a*x*y))
   element_pow_zn(sig->C, sig->A, server->x);
   element_mul(z1, a, server->x);
   element_mul(z1, z1, server->y);
   element_pow_zn(g1, msg->M, z1);
   element_mul(sig->C, sig->C, g1);

   // sig = A, B, ZB, C
   debugf("A = %B", sig->A);
   debugf("B = %B", sig->B);
   debugf("ZB = %B", sig->ZB);
   debugf("C = %B", sig->C);

   element_clear(g1);
   element_clear(a);
   element_clear(z1);

   return 1;
}

int server_verify_login_msg(struct public_params *pub, struct server_secret *server, struct login_msg *msg)
{
   int rc = 1;
   unsigned char hash[32];
   element_t lhs, rhs;
   element_t vs, vx, vxy, vxyz;
   element_t c, t, t2;
   element_t gt, z1;

   debugf("t = %ld", msg->t);

   element_init_Zr(t, pub->p);
   element_init_Zr(t2, pub->p);
   element_init_GT(lhs, pub->p);
   element_init_GT(rhs, pub->p);
   element_init_Zr(c, pub->p);
   element_init_Zr(z1, pub->p);
   element_init_GT(gt, pub->p);
   element_init_GT(vs, pub->p);
   element_init_GT(vx, pub->p);
   element_init_GT(vxy, pub->p);
   element_init_GT(vxyz, pub->p);
   // Verify the structure
   // Unpack
   // check: current epoch == t
   get_fuzzy_epoch(t, t2);
   if (element_cmp(t, msg->t) < 0 || element_cmp(msg->t, t2) < 0) {
      // If we aren't too far off that's kind of ok...
#if (!BENCHMARK)
      errorf("t doesn't match %B vs %B", t, msg->t);
      rc = 0;
      goto out;
#endif
   }

   // check: A != 1
   if (!element_cmp(msg->A, G_one)) {
      error("A can't be one - invalid signature!");
      rc = 0;
      goto out;
   }
   // check: e(Y, A) == e(g, B)
   pairing_pp_apply(lhs, msg->A, pub->pp.Y);
   pairing_pp_apply(rhs, msg->B, pub->pp.g);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid structure");
      rc = 0;
      goto out;
   }
   // check: e(Z, B) == e(g, ZB)
   pairing_pp_apply(lhs, msg->B, pub->pp.Z);
   pairing_pp_apply(rhs, msg->ZB, pub->pp.g);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid structure");
   }

   // Verify the signature
   debug("Verify sig");
   // vs = e(g, C)
   pairing_pp_apply(vs, msg->C, pub->pp.g);
   // vx = e(X, At)
   pairing_pp_apply(vx, msg->A, pub->pp.X);
   // vxy = e(X, Bt)
   pairing_pp_apply(vxy, msg->B, pub->pp.X);
   // vxyz = e(X, ZBt)
   pairing_pp_apply(vxyz, msg->ZB, pub->pp.X);

   // c = hash(vs, vx, vxy, vxyz, R1, gT, Yt, R2)
   hash_elements(hash, (element_t *[]){&vs, &vx, &vxy, &vxyz, &pub->gt,
            &msg->R1, &msg->Yt, &msg->R2, NULL});
   element_from_hash(c, hash, 32);
   debugf("c = %B", c);

   // check: (vx ** c) * R1 == (vs ** rrr2) * (vxy ** rrd) * (vxyz *** rrr)
   element_pow_zn(lhs, vx, c);
   element_mul(lhs, lhs, msg->R1);
   debugf("(vx ** c) * R1 = %B", lhs);

   element_pow_zn(rhs, vs, msg->r2);
   element_pow_zn(gt, vxy, msg->d);
   element_mul(rhs, rhs, gt);
   element_pow_zn(gt, vxyz, msg->r);
   element_mul(rhs, rhs, gt);
   debugf("(vs ** rrr2) * (vxy ** rrd) * (vxyz *** rrr) = %B", rhs);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid signature");
      rc = 0;
      goto out;
   }

   // check: (gT ** (-c)) * R2 == Yt ** (rrd - (c * t))
   element_mul_si(z1, c, -1);
   element_pow_zn(lhs, pub->gt, z1);
   element_mul(lhs, lhs, msg->R2);
   debugf("(gT ** (-c)) * R2 = %B", lhs);

   element_mul(z1, c, msg->t);
   element_mul_si(z1, z1, -1);
   element_add(z1, msg->d, z1);
   element_pow_zn(rhs, msg->Yt, z1);
   debugf("Yt ** (rrd - (c * t)) = %B", rhs);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid token");
      rc = 0;
      goto out;
   }

 out:
   element_clear(lhs);
   element_clear(rhs);
   element_clear(t);
   element_clear(t2);
   element_clear(c);
   element_clear(gt);
   element_clear(z1);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);
   return rc;
}

int server_verify_reup_msg(struct public_params *pub, struct reup_msg *msg)
{
   int rc = 1;
   element_t t, t2;
   unsigned char hash[32];
   element_t c, neg_c;
   element_t gc, z1;
   element_t lhs, rhs;

   element_init_Zr(t, pub->p);
   element_init_Zr(t2, pub->p);
   element_init_Zr(c, pub->p);
   element_init_Zr(neg_c, pub->p);
   element_init_Zr(z1, pub->p);
   element_init_GT(lhs, pub->p);
   element_init_GT(rhs, pub->p);
   element_init_GT(gc, pub->p);
   get_fuzzy_epoch(t, t2);
   if (element_cmp(t, msg->t) < 0 && element_cmp(msg->t, t2) < 0) {
      // If we aren't too far off that's kind of ok...
#if (!BENCHMARK)
      errorf("t doesn't match %B vs %B", t, msg->t);
      rc = 0;
      goto out;
#endif
   }

   // c = hash(Yt, Rt, Ys, Rs)
   hash_elements(hash, (element_t *[]){&msg->Yt, &msg->Rt, &msg->Ys, &msg->Rs, NULL});
   element_from_hash(c, hash, 32);
   element_mul_si(neg_c, c, -1);

   element_pow_zn(gc, pub->gt, neg_c);

   element_mul(z1, neg_c, msg->t);
   element_add(z1, z1, msg->a);

   // There appears to be some parallism that could let us batch some of this
   // check: (gT ** (-c)) * R == Yt ** (a - (c * t))
   element_mul(lhs, gc, msg->Rt);
   element_pow_zn(rhs, msg->Yt, z1);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid current token!");
      rc = 0;
      goto out;
   }

   // Yt+1
   // check: (gT ** (-c)) * R == Ys ** (a - (c * t) - c)
   element_add(z1, z1, neg_c);

   element_mul(lhs, gc, msg->Rs);
   element_pow_zn(rhs, msg->Ys, z1);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid next token!");
      rc = 0;
      goto out;
   }

 out:
   element_clear(lhs);
   element_clear(rhs);
   element_clear(t);
   element_clear(t2);
   element_clear(c);
   element_clear(neg_c);
   element_clear(gc);
   element_clear(z1);
   return rc;
}

int server_verify_multi_msg(struct public_params *pub, struct server_secret *server, struct multi_msg *msg)
{
   int i, rc = 1;
   unsigned char hash[32];
   element_t lhs, rhs;
   element_t vs, vx, vxy, vxyz;
   element_t c, neg_c, t, t2;
   element_t gt, gc, z1;
   element_t **arr = malloc((msg->epochs*2 + 7) * sizeof(*arr));

   debugf("t = %ld", msg->t);

   element_init_Zr(t, pub->p);
   element_init_Zr(t2, pub->p);
   element_init_GT(lhs, pub->p);
   element_init_GT(rhs, pub->p);
   element_init_Zr(c, pub->p);
   element_init_Zr(neg_c, pub->p);
   element_init_Zr(z1, pub->p);
   element_init_GT(gt, pub->p);
   element_init_GT(gc, pub->p);
   element_init_GT(vs, pub->p);
   element_init_GT(vx, pub->p);
   element_init_GT(vxy, pub->p);
   element_init_GT(vxyz, pub->p);

   // Verify the structure
   // Unpack
   // check: current epoch == t
   get_fuzzy_epoch(t, t2);
   if (element_cmp(t, msg->t) && element_cmp(t2, msg->t)) {
      // If we aren't too far off that's kind of ok...
#if (!BENCHMARK)
      errorf("t doesn't match %B vs %B", t, msg->t);
      rc = 0;
      goto out;
#endif
   }

   // check: A != 1
   if (!element_cmp(msg->A, G_one)) {
      error("A can't be one - invalid signature!");
      rc = 0;
      goto out;
   }
   // check: e(Y, A) == e(g, B)
   pairing_pp_apply(lhs, msg->A, pub->pp.Y);
   pairing_pp_apply(rhs, msg->B, pub->pp.g);
   /* element_pairing(lhs, pub->Y, msg->A); */
   /* element_pairing(rhs, pub->g, msg->B); */
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid structure");
      rc = 0;
      goto out;
   }
   // check: e(Z, B) == e(g, ZB)
   pairing_pp_apply(lhs, msg->B, pub->pp.Z);
   pairing_pp_apply(rhs, msg->ZB, pub->pp.g);
   /* element_pairing(lhs, pub->Z, msg->B); */
   /* element_pairing(rhs, pub->g, msg->ZB); */
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid structure");
   }

   // Verify the signature
   debug("Verify sig");
   // vs = e(g, C)
   pairing_pp_apply(vs, msg->C, pub->pp.g);
   /* element_pairing(vs, pub->g, msg->C); */
   // vx = e(X, At)
   pairing_pp_apply(vx, msg->A, pub->pp.X);
   /* element_pairing(vx, pub->X, msg->A); */
   // vxy = e(X, Bt)
   pairing_pp_apply(vxy, msg->B, pub->pp.X);
   /* element_pairing(vxy, pub->X, msg->B); */
   // vxyz = e(X, ZBt)
   pairing_pp_apply(vxyz, msg->ZB, pub->pp.X);
   /* element_pairing(vxyz, pub->X, msg->ZB); */

   // c = hash(vs, vx, vxy, vxyz, R1, Yt, R2)
   debug("Starting to hash");
   arr[0] = &vs;
   arr[1] = &vx;
   arr[2] = &vxy;
   arr[3] = &vxyz;
   arr[4] = &pub->gt;
   arr[5] = &msg->R1;
   for (i = 0; i < msg->epochs; i++) {
      arr[6 + 2*i] = &msg->Y[i];
      arr[6 + 2*i + 1] = &msg->Y[i];
   }
   arr[6 + 2*i] = NULL;
   hash_elements(hash, arr);
   element_from_hash(c, hash, 32);
   debugf("c = %B", c);

   // check: (vx ** c) * R1 == (vs ** rrr2) * (vxy ** rrd) * (vxyz *** rrr)
   element_pow_zn(lhs, vx, c);
   element_mul(lhs, lhs, msg->R1);
   debugf("(vx ** c) * R1 = %B", lhs);

   element_pow_zn(rhs, vs, msg->r2);
   element_pow_zn(gt, vxy, msg->d);
   element_mul(rhs, rhs, gt);
   element_pow_zn(gt, vxyz, msg->r);
   element_mul(rhs, rhs, gt);
   debugf("(vs ** rrr2) * (vxy ** rrd) * (vxyz *** rrr) = %B", rhs);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid signature");
      rc = 0;
      goto out;
   }

   // check: (gT ** (-c)) * R[i] == Y[i] ** (rrd - (c * t))
   element_mul_si(neg_c, c, -1);
   element_pow_zn(gc, pub->gt, neg_c);

   element_mul(z1, c, msg->t);
   element_sub(z1, msg->d, z1);

   for (i = 0; i < msg->epochs; i++) {
      element_mul(lhs, gc, msg->R[i]);
      element_pow_zn(rhs, msg->Y[i], z1);
      if (element_cmp(lhs, rhs)) {
         error("left and right don't match - invalid token");
         rc = 0;
         goto out;
      }
      element_add(z1, z1, neg_c);
   }

 out:
   element_clear(lhs);
   element_clear(rhs);
   element_clear(t);
   element_clear(t2);
   element_clear(c);
   element_clear(neg_c);
   element_clear(gc);
   element_clear(gt);
   element_clear(z1);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);

   free(arr);

   return rc;
}
