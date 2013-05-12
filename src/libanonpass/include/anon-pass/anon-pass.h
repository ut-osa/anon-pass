#ifndef __ANON_PASS_H
#define __ANON_PASS_H

#include <pbc/pbc.h>
#include <stdint.h>

struct pp_params
{
   pairing_pp_t g, X, Y, Z;
};
struct public_params
{
   pairing_t p;
   element_t g, gt;
   element_t X, Y, Z, W;
   struct pp_params pp;
};
#define RAW_PARAM_LEN 640
struct register_msg
{
   element_t M, R;
   element_t rg, rZ;
};
#define RAW_REG_MSG_LEN 296
struct client_precompute
{
   element_t A, B, ZB, C;
};
struct register_sig
{
   element_t A, B, ZB, C;
   struct client_precompute client;
};
#define RAW_REG_SIG_LEN 512
struct login_msg
{
   // Signature
   element_t A, B, ZB, C;
   // Proof
   element_t d, r, r2, R1;
   element_t Yt, R2;
   element_t t;
};
#define RAW_LOGIN_LEN 976
struct reup_msg
{
   // Current
   element_t Yt, Rt;
   // Next
   element_t Ys, Rs;
   // Sig
   element_t a;
   element_t t;
};
#define RAW_REUP_LEN 552
struct multi_msg
{
   // Signature
   element_t A, B, ZB, C;
   // Proof
   element_t d, r, r2, R1;
   element_t t;
   element_t *Y, *R;
   int epochs;
};
#define MAX_MSG_LEN RAW_LOGIN_LEN

void pairing_init(pairing_t, FILE *);
int  pub_init(struct public_params *, FILE *);
int  pub_pp_init(struct public_params *pub);
void reg_msg_init(struct public_params *, struct register_msg *);
void reg_sig_init(struct public_params *, struct register_sig *);
void login_msg_init(struct public_params *, struct login_msg *);
void reup_msg_init(struct public_params *, struct reup_msg *);

void pub_clear(struct public_params *);
void reg_msg_clear(struct register_msg *);
void reg_sig_clear(struct register_sig *, int);
void login_msg_clear(struct login_msg *);
void reup_msg_clear(struct reup_msg *);

void hash_element(unsigned char *, element_t);
void hash_elements(unsigned char *, element_t *[]);
long set_offset(long);
long get_epoch(element_t);
long get_fuzzy_epoch(element_t, element_t);
void set_epoch(element_t, long);

#define INT_BASE 36
#define ELE_BASE 36
#define TIME_PERIOD 15

#endif /* __ANON_PASS_H */
