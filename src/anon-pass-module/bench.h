#ifndef _ANON_PASS_DEBUG_H_
#define _ANON_PASS_DEBUG_H_

/* #define BENCH_REG */
#define REQ_BENCH

/* self contained benchmarking infrastructure */
#if (defined BENCH_REG || defined BENCH_LOG || defined BENCH_RUP)
#define BENCH
#endif

#define MAX_RECORD 1050

enum timer_types {
    reg=0,
    log,
    rup,
    MAX_TIMER,
};
const char request_name[MAX_TIMER+1][6] = {
   "reg", "log", "rup",
   "MAX",};

struct log_entry {
    unsigned short tot;
    unsigned short hs;
    unsigned short sig;
    unsigned short ver;
};

#ifdef BENCH
static char request_log_name[128] = {0};
struct log_entry log_entries[MAX_RECORD];
ngx_int_t cur_entry = 0;
#endif
#ifdef REQ_BENCH
static FILE *request_log = NULL;
static long last_bench = 0;
uint64_t request_count[MAX_TIMER] = {0};
uint64_t request_pass[MAX_TIMER] = {0};
#endif

#if (DEBUG)
void callout_buffer(uint8_t *buffer, size_t sz)
{
    size_t i;
    fprintf(stderr, "\n\n@@@\n");
    for (i = 0; i < sz; i++) {
        fprintf(stderr, "%02x", (uint8_t)buffer[i]);
        if ((i + 1) % 32 == 0) fprintf(stderr, "\n");
        else if ((i + 1) % 8 == 0) fprintf(stderr, "\t");
        else if ((i + 1) % 2 == 0) fprintf(stderr, " ");
    }
    if (i % 32) fprintf(stderr, "\n");
    fprintf(stderr, "@@@\n\n");
}
#endif

#endif
