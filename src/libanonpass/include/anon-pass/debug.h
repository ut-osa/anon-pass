#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdio.h>
#include <sys/time.h>

#include <stdint.h>

#define DEBUG_STREAM stderr

#if (DEBUG)
#define debug(fmt)       element_fprintf(DEBUG_STREAM, "[DEBUG] %s: %s\n", __FUNCTION__, fmt)
#define debugf(fmt, ...) element_fprintf(DEBUG_STREAM, "[DEBUG] %s: " fmt "\n", __FUNCTION__, __VA_ARGS__)
#define output(fmt)      element_fprintf(DEBUG_STREAM, "[OUT] %s\n", fmt);
#define outputf(fmt, ...)element_fprintf(DEBUG_STREAM, "[OUT] " fmt "\n", __VA_ARGS__);
#define error(fmt)       element_fprintf(DEBUG_STREAM, "[ERROR] %s: %s\n", __FUNCTION__, fmt)
#define errorf(fmt, ...) element_fprintf(DEBUG_STREAM, "[ERROR] %s: " fmt "\n", __FUNCTION__, __VA_ARGS__)
#define timef(fmt, ...)                                                 \
   do {                                                                 \
      struct timeval tv = {0,0};                                        \
      gettimeofdaY(&tv, NULL);                                          \
      fprintf(DEBUG_STREAM, "[%02ld:%02ld:%02ld.%06ld] %s: " fmt "\n",  \
              (tv.tv_sec / 3600) % 24, (tv.tv_sec / 60) % 60,           \
              tv.tv_sec % 60, tv.tv_usec, __func__, __VA_ARGS__);       \
   } while (0)
#else
#define debug(fmt)       do {} while (0)
#define debugf(fmt, ...) do {} while (0)
#define output(fmt)      element_fprintf(DEBUG_STREAM, "%s\n", fmt);
#define outputf(fmt, ...)element_fprintf(DEBUG_STREAM, fmt "\n", __VA_ARGS__);
#define error(fmt)       element_fprintf(stderr, "[ERROR] %s: %s\n", __FUNCTION__, fmt)
#define errorf(fmt, ...) element_fprintf(stderr, "[ERROR] %s: " fmt "\n", __FUNCTION__, __VA_ARGS__)
#define timef(fmt, ...)                                                 \
   do {                                                                 \
      struct timeval tv;                                                \
      gettimeofday(&tv, NULL);                                          \
      fprintf(stderr, "[%02ld:%02ld:%02ld.%06ld] %s: " fmt "\n",        \
              (tv.tv_sec / 3600) % 24, (tv.tv_sec / 60) % 60,           \
              tv.tv_sec % 60, tv.tv_usec, __func__, __VA_ARGS__);       \
   } while (0)
#endif

#if (BENCHMARK)
#define time_code(label, sub, iters, code)                              \
   do {                                                                 \
      struct timeval tv1 = {0}, tv2 = {0};                              \
      uint64_t time, i;                                                 \
      gettimeofday(&tv1, NULL);                                         \
      for (i = 0; i < iters; i++) {                                     \
         code;                                                          \
      }                                                                 \
      gettimeofday(&tv2, NULL);                                         \
      time = 1000000 * (tv2.tv_sec - tv1.tv_sec) + tv2.tv_usec - tv1.tv_usec; \
      outputf(""#label "-"#sub ":\t%ld.%06ld s"                         \
              "\t-> %ld.%03ld ms",                                      \
              time / 1000000, time % 1000000,                           \
              (time / iters) / 1000, (time / iters) % 1000);            \
   } while (0)
#define make_timer(label,sub)                   \
   static uint64_t __count_##label[sub] = {0};  \
   static uint64_t __time_##label[sub] = {0};   \
   static int __max_##label = sub
#define add_timer(label,sub,code)                                       \
   do {                                                                 \
      struct timeval tv1 = {0,0}, tv2 = {0,0};                          \
      uint64_t time;                                                    \
      gettimeofday(&tv1, NULL);                                         \
      code;                                                             \
      gettimeofday(&tv2, NULL);                                         \
      time = 1000000 * (tv2.tv_sec - tv1.tv_sec) + tv2.tv_usec - tv1.tv_usec; \
      __count_##label[sub]++;                                           \
      __time_##label[sub] += time;                                      \
   } while (0)
#define print_timer(label,sub)                                          \
   do {                                                                 \
      outputf(""#label "-"#sub ":\t%ld.%06ld s", __time_##label[sub] / 1000000, \
              __time_##label[sub] % 1000000);                           \
      outputf("\t-> %ld.%03ld ms", (__time_##label[sub] / __count_##label[sub]) / 1000, \
              (__time_##label[sub] / __count_##label[sub]) % 1000);     \
   } while (0)
#define print_timers(label)                                             \
   do {                                                                 \
      uint64_t _count = 0, _time = 0;                                   \
      int i;                                                            \
      for (i = 0; i < __max_##label; i++)                               \
         if (__count_##label[i]) {                                      \
            _time += __time_##label[i];                                 \
            _count += __count_##label[i];                               \
         }                                                              \
      outputf(""#label ":\t%ld.%06ld s", _time / 1000000, _time % 1000000); \
      outputf("\t-> %ld.%03ld ms", (_time / _count) / 1000, (_time / _count) % 1000); \
   } while (0)

#define reset_timer(label,sub)                  \
   do {                                         \
      __count_##label[sub] = 0;                 \
      __time_##label[sub] = 0;                  \
   } while (0)
#else
#define time_code(label, sub, iters, code)                              \
   do {                                                                 \
      uint64_t i;                                                       \
      for (i = 0; i < iters; i++) {                                     \
         code;                                                          \
      }                                                                 \
   } while (0)
#define make_timer(label,sub) struct __dummy_##label##sub {}
#define add_timer(label,sub,code) code
#define print_timer(label,sub) do {} while (0)
#define print_timers(label) do {} while (0)
#define reset_timer(label,sub) do {} while (0)
#endif /* (BENCHMARK) */

#endif
