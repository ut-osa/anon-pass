#include <anon-pass/debug.h>
#include <anon-pass/server.h>
#include <anon-pass/client.h>
#include <anon-pass/anon-pass.h>

static element_t one;
static element_t G_one;

uint64_t delta(struct timeval *s, struct timeval *e)
{
   return 1000000*(e->tv_sec - s->tv_sec) + e->tv_usec - s->tv_usec;
}

void init_one(struct public_params *pub)
{
   element_init_Zr(one, pub->p);
   element_set1(one);

   element_init_G1(G_one, pub->p);
   element_set1(G_one);
}
long client_create_login_msg_base(struct public_params *pub,
                                      struct client_secret *client,
                             struct register_sig *sig, struct login_msg *msg)
{
   // Input: t, A, B, ZB, C
   // Random Params: rd, rr, rr2, b1, b2
   long epoch = 0;
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
   epoch = get_epoch(msg->t);

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
   // First pair
   element_pairing(vs, msg->C, pub->g);
   element_pairing(vx, msg->A, pub->X);
   element_pairing(vxy, msg->B, pub->X);
   element_pairing(vxyz, msg->ZB, pub->X);
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
   //element_mul(msg->r2, msg->r2, c);
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

long client_create_login_msg_pp(struct public_params *pub,
                                      struct client_secret *client,
                             struct register_sig *sig, struct login_msg *msg)
{
   // Input: t, A, B, ZB, C
   // Random Params: rd, rr, rr2, b1, b2
   long epoch = 0;
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
   epoch = get_epoch(msg->t);

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
   // First pair
   pairing_pp_apply(vs, msg->C, pub->pp.g);
   pairing_pp_apply(vx, msg->A, pub->pp.X);
   pairing_pp_apply(vxy, msg->B, pub->pp.X);
   pairing_pp_apply(vxyz, msg->ZB, pub->pp.X);
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
   //element_mul(msg->r2, msg->r2, c);
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

long client_create_login_msg_sig(struct public_params *pub,
                                      struct client_secret *client,
                             struct register_sig *sig, struct login_msg *msg)
{
   // Input: t, A, B, ZB, C
   // Random Params: rd, rr, rr2, b1, b2
   long epoch = 0;
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
   epoch = get_epoch(msg->t);

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
   // First pair
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
   //element_mul(msg->r2, msg->r2, c);
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

int server_verify_login_msg_base(struct public_params *pub, struct server_secret *server, struct login_msg *msg)
{
   int rc = 1;
   unsigned char hash[32];
   element_t lhs, rhs;
   element_t vs, vx, vxy, vxyz;
   element_t c, t;
   element_t gt, z1;

   debugf("t = %ld", msg->t);

   element_init_Zr(t, pub->p);
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
   get_epoch(t);
   if (element_cmp(t, msg->t)) {
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
   element_pairing(lhs, msg->A, pub->Y);
   element_pairing(rhs, msg->B, pub->g);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid structure");
      rc = 0;
      goto out;
   }
   // check: e(Z, B) == e(g, ZB)
   element_pairing(lhs, msg->B, pub->Z);
   element_pairing(rhs, msg->ZB, pub->g);
   if (element_cmp(lhs, rhs)) {
      error("left and right don't match - invalid structure");
   }

   // Verify the signature
   debug("Verify sig");
   // vs = e(g, C)
   element_pairing(vs, msg->C, pub->g);
   // vx = e(X, At)
   element_pairing(vx, msg->A, pub->X);
   // vxy = e(X, Bt)
   element_pairing(vxy, msg->B, pub->X);
   // vxyz = e(X, ZBt)
   element_pairing(vxyz, msg->ZB, pub->X);

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
   element_clear(c);
   element_clear(gt);
   element_clear(z1);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);
   return rc;
}

int server_verify_login_msg_pp(struct public_params *pub, struct server_secret *server, struct login_msg *msg)
{
   int rc = 1;
   unsigned char hash[32];
   element_t lhs, rhs;
   element_t vs, vx, vxy, vxyz;
   element_t c, t;
   element_t gt, z1;

   debugf("t = %ld", msg->t);

   element_init_Zr(t, pub->p);
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
   get_epoch(t);
   if (element_cmp(t, msg->t)) {
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
   element_clear(c);
   element_clear(gt);
   element_clear(z1);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);
   return rc;
}

int server_verify_login_msg_sig(struct public_params *pub, struct server_secret *server, struct login_msg *msg)
{
   int rc = 1;
   unsigned char hash[32];
   element_t lhs, rhs;
   element_t vs, vx, vxy, vxyz;
   element_t c, t;
   element_t gt, z1;

   debugf("t = %ld", msg->t);

   element_init_Zr(t, pub->p);
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
   get_epoch(t);
   if (element_cmp(t, msg->t)) {
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
   element_clear(c);
   element_clear(gt);
   element_clear(z1);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);
   return rc;
}

/* Multi message */

int client_create_multi_msg_naive(struct public_params *pub, struct client_secret *client,
                            struct register_sig *sig, struct login_msg *msg,
                            struct reup_msg *rup, int no_epochs)
{
   struct timeval start, end;
   int i;
   long epoch = client_create_login_msg(pub, client, sig, msg, 0);
   gettimeofday(&start, NULL);
   for (i = 0; i < no_epochs - 1; i++) {
      client_create_reup_msg(pub, client, &rup[i], epoch++);
   }
   gettimeofday(&end, NULL);

   return delta(&start, &end);
}

int server_verify_multi_msg_naive(struct public_params *pub, struct server_secret *server,
                            struct login_msg *msg, struct reup_msg *rup, int no_epochs)
{
   struct timeval start, end;
   int i;
   if (server_verify_login_msg(pub, server, msg) == 0) {
      printf("failed login\n");
      goto out;
   }
   gettimeofday(&start, NULL);
   for (i = 0; i < no_epochs - 1; i++) {
      if (server_verify_reup_msg(pub, &rup[i]) == 0) {
         printf("failed reup %d\n", i);
         /* goto out; */
      }
   }
   gettimeofday(&end, NULL);
 out:
   return delta(&start, &end);
}


long client_create_multi_msg_opt(struct public_params *pub, struct client_secret *client,
                            struct register_sig *sig, struct multi_msg *msg,
                            int no_epochs)
{
   struct timeval start, end;
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

   gettimeofday(&start, NULL);
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
   gettimeofday(&end, NULL);

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

   return delta(&start, &end);
}

long server_verify_multi_msg_opt(struct public_params *pub, struct server_secret *server, struct multi_msg *msg)
{
   struct timeval start, end;
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
   gettimeofday(&start, NULL);
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
   gettimeofday(&end, NULL);

 out:
   element_clear(lhs);
   element_clear(rhs);
   element_clear(t);
   element_clear(t2);
   element_clear(c);
   element_clear(neg_c);
   element_clear(gt);
   element_clear(z1);
   element_clear(vs);
   element_clear(vx);
   element_clear(vxy);
   element_clear(vxyz);

   free(arr);

   return delta(&start, &end);
}
