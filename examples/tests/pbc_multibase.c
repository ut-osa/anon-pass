#include <pbc/pbc.h>
#include <gmp.h>
#include <stdio.h>

#include <anon-pass/debug.h>

#define N_ITERS 10000

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int element_equal(element_ptr e1,
                         element_ptr e2)
{
   int result;
   element_t x;

   element_init_same_as(x, e1);
   element_sub(x, e1, e2);

   result = element_is0(x);

   element_clear(x);
   return result;
}

void naive_pow(element_ptr result, element_ptr b, element_ptr e)
{
   int s;
   mpz_t e_mpz;

   mpz_init(e_mpz);
   element_to_mpz(e_mpz, e);

   element_init_same_as(result, b);
   element_set1(result);

   for (s = mpz_sizeinbase(e_mpz, 2) - 1; s >= 0; s--) {
      element_square(result, result);
      if (mpz_tstbit(e_mpz, s))
         element_mul(result, result, b);
   }

   mpz_clear(e_mpz);
}

/* XXX: allow selection of PBC optimized exponentiation versus naive
   repeated squaring exponentiation */
void naive_two_base_exp(element_ptr result,
                        element_ptr b1, element_ptr e1, element_ptr b2, element_ptr e2)
{
   element_t b1_pow, b2_pow;

   element_init_same_as(b1_pow, b1);
   element_init_same_as(b2_pow, b1);

   /* element_pow_zn(b1_pow, b1, e1); */
   /* element_pow_zn(b2_pow, b2, e2); */
   naive_pow(b1_pow, b1, e1);
   naive_pow(b2_pow, b2, e2);
   element_mul(result, b1_pow, b2_pow);

   element_clear(b1_pow);
   element_clear(b2_pow);
}

void two_base_exp(element_ptr result,
                  element_ptr b1, element_ptr e1, element_ptr b2, element_ptr e2)
{
   int i, s1, s2, s;
   element_t base_combos[4];

   mpz_t e1_mpz, e2_mpz;

   mpz_init(e1_mpz);
   element_to_mpz(e1_mpz, e1);
   mpz_init(e2_mpz);
   element_to_mpz(e2_mpz, e2);

   for (i = 0; i < 4; i++) {
      element_init_same_as(base_combos[i], b1);
   }
   element_set1(base_combos[0]);
   element_set(base_combos[1], b1);
   element_set(base_combos[2], b2);
   element_mul(base_combos[3], b1, b2);

   element_set1(result);

   s1 = mpz_sizeinbase(e1_mpz, 2);
   s2 = mpz_sizeinbase(e2_mpz, 2);
   s = MAX(s1, s2) - 1;

   for (; s >= 0; s--) {
      int which_combo;

      element_square(result, result);

      which_combo = (mpz_tstbit(e2_mpz, s) << 1) + mpz_tstbit(e1_mpz, s);
      element_mul(result, result, base_combos[which_combo]);
   }

   for (i = 0; i < 4; i++) {
      element_clear(base_combos[i]);
   }
   mpz_clear(e1_mpz);
   mpz_clear(e2_mpz);
}

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

void test_two_base_exp_works(void)
{
   char param_type[] = "param/a.param";

   int i;
   pairing_t p;
   element_t b1, b2, e1, e2, result1, result2;
   pairing_init(p, fopen(param_type, "r"));

   element_init_G1(b1, p);
   element_init_G1(b2, p);
   /* element_init_Zr(b1, p); */
   /* element_init_Zr(b2, p); */
   element_init_Zr(e1, p);
   element_init_Zr(e2, p);
   element_init_same_as(result1, b1);
   element_init_same_as(result2, b1);

   for (i = 0; i < 100; i++) {
      element_random(b1);
      element_random(b2);
      element_random(e1);
      element_random(e2);

      naive_two_base_exp(result1, b1, e1, b2, e2);
      two_base_exp(result2, b1, e1, b2, e2);

      if (!element_equal(result1, result2)) {
         error("Two exponentiation methods disagree!");
         exit(1);
      }
   }
}

int main()
{
   test_two_base_exp_works();

   char param_type[] = "param/a.param";

   pairing_t p;
   element_t b1, b2, e1, e2, result;
   pairing_init(p, fopen(param_type, "r"));

   element_init_G1(b1, p);
   element_init_G1(b2, p);
   element_init_Zr(e1, p);
   element_init_Zr(e2, p);
   element_init_same_as(result, b1);

   element_random(b1);
   element_random(b2);
   element_random(e1);
   element_random(e2);

   time_code(, MULTI_EXP, (N_ITERS / 10),
             two_base_exp(result, b1, e1, b2, e2);
             );
   time_code(, NAIVE_MULTI_EXP, (N_ITERS / 10),
             naive_two_base_exp(result, b1, e1, b2, e2);
             );

   return 0;
}
