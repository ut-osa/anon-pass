#include <pbc/pbc.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include <anon-pass/debug.h>

#define N_ITERS 10000

void pairing_init(pairing_t p, FILE *f);
void time_ops(element_t, element_t, element_t);

char *param_types[] = {
   "param/a.param",
   "param/d159.param",
   "param/d201.param",
   "param/d224.param",
   "param/e.param",
   "param/f.param",
   "param/a1.param",
   NULL};

int main(int argc, char *argv[])
{
   pairing_t p;
   element_t e1, e2, et, z;
   char **type = NULL;
   for (type = param_types; *type != NULL; type ++) {
      printf("Pairing Type: %s\n", *type);
      pairing_init(p, fopen(*type, "r"));
      element_init_G1(e1, p);
      element_init_G2(e2, p);
      element_init_GT(et, p);
      element_init_Zr(z, p);
      element_random(e1);
      element_random(e2);
      element_random(et);
      element_random(z);

      time_ops(e1, e1, z);
      printf("\n");
      time_ops(e2, e2, z);
      printf("\n");
      time_ops(et, et, z);
      printf("\n");

      element_clear(e1);
      element_clear(e2);
      element_clear(et);
      element_clear(z);
      pairing_clear(p);
      printf("\n");
   }
   return 0;
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

/* Timed test for different operations */
void time_ops(element_t e1, element_t e2, element_t z)
{
   /* For EC groups, "addition" is multiplication/the group operation
      (see field_init_curve_ab in ecc/curve.c) */

   /* Addition */
   /* time_code(, ADD, N_ITERS, */
   /*           element_add(e1, e1, e2); */
   /*           ); */

   /* Multiplication */
   time_code(, MULT, N_ITERS,
             element_mul(e1, e1, e2);
             );

   /* Exponentiation */
   time_code(, EXP, (N_ITERS / 10),
             element_pow_zn(e1, e1, z);
             );
}
