#include <stdio.h>
#include <pbc/pbc.h>
#include <sys/time.h>
#include <stdint.h>
#include <anon-pass/debug.h>
#include <anon-pass/anon-pass.h>

#define DEFAULT_PARAMS "param/a.param"
#define NR_ITERS 1000

uint64_t delta(struct timeval *s, struct timeval *e)
{
   return 1000000*(e->tv_sec - s->tv_sec) + e->tv_usec - s->tv_usec;
}

int main() {
   int i;
   pairing_t p;
   element_t g1, g2, g3;
   element_t t1, t2, t3, z1;
   struct timeval start, end;
   uint64_t g_mul = 0, g_pow = 0, t_mul = 0, t_pow = 0, g_pair = 0;
   pairing_init(p, fopen(DEFAULT_PARAMS, "r"));
   element_init_G1(g1, p);
   element_init_G1(g2, p);
   element_init_G1(g3, p);
   element_init_GT(t1, p);
   element_init_GT(t2, p);
   element_init_GT(t3, p);
   element_init_Zr(z1, p);

   for (i = 0; i < NR_ITERS; i++) {
      element_random(g1);
      element_random(g2);
      gettimeofday(&start, NULL);
      element_mul(g3, g1, g2);
      gettimeofday(&end, NULL);
      g_mul += delta(&start, &end);
   }
   printf("g mul: %ld %ld\n", g_mul, g_mul / NR_ITERS);

   for (i = 0; i < NR_ITERS; i++) {
      element_random(g1);
      element_random(z1);
      gettimeofday(&start, NULL);
      element_pow_zn(g2, g1, z1);
      gettimeofday(&end, NULL);
      g_pow += delta(&start, &end);
   }
   printf("g pow: %ld %ld\n", g_pow, g_pow / NR_ITERS);


   for (i = 0; i < NR_ITERS; i++) {
      element_random(t1);
      element_random(t2);
      gettimeofday(&start, NULL);
      element_mul(t3, t1, t2);
      gettimeofday(&end, NULL);
      t_mul += delta(&start, &end);
   }
   printf("t mul: %ld %ld\n", t_mul, t_mul / NR_ITERS);

   for (i = 0; i < NR_ITERS; i++) {
      element_random(t1);
      element_random(z1);
      gettimeofday(&start, NULL);
      element_pow_zn(t2, t1, z1);
      gettimeofday(&end, NULL);
      t_pow += delta(&start, &end);
   }
   printf("t pow: %ld %ld\n", t_pow, t_pow / NR_ITERS);


   for (i = 0; i < NR_ITERS; i++) {
      element_random(g1);
      element_random(g2);
      gettimeofday(&start, NULL);
      element_pairing(t1, g1, g2);
      gettimeofday(&end, NULL);
      g_pair += delta(&start, &end);
   }
   printf("g pair: %ld %ld\n", g_pair, g_pair / NR_ITERS);

   return 0;
}
