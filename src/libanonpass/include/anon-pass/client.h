#ifndef __CLIENT_H
#define __CLIENT_H

#include <pbc/pbc.h>
#include "anon-pass.h"

struct client_secret
{
   element_t d, r;
};

void client_init_one(struct public_params *);
int client_init(struct public_params *, struct client_secret *,
                struct register_sig *, FILE *);
void client_clear(struct client_secret *);
void client_clear_one(void);

int client_verify_pub(struct public_params *);
int client_create_reg_msg(struct public_params *, struct client_secret *,
                          struct register_msg *);
int client_verify_reg_sig(struct public_params *, struct client_secret *,
                          struct register_sig *);
int client_precompute_reg_sig(struct public_params *, struct client_secret *,
                              struct register_sig *);
int client_save_reg_sig(struct register_sig *, FILE *);
long client_create_login_msg(struct public_params *, struct client_secret *,
                             struct register_sig *, struct login_msg *, long);
long client_create_reup_msg(struct public_params *, struct client_secret *,
                            struct reup_msg *, long);
int client_create_multi_msg(struct public_params *, struct client_secret *,
                            struct register_sig *, struct multi_msg *, int);

#endif /* __CLIENT_H */
