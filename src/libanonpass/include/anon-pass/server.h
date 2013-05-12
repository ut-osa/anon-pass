#ifndef __SERVER_H
#define __SERVER_H

#include <pbc/pbc.h>
#include "anon-pass.h"

struct server_secret
{
   element_t x, y, z;
};

void server_init(struct public_params *, struct server_secret *, FILE *, FILE *);
void server_clear(struct server_secret *);

int server_verify_reg_msg(struct public_params *, struct server_secret *,
                          struct register_msg *);
int server_sign_reg_msg(struct public_params *, struct server_secret *,
                        struct register_msg *, struct register_sig *);
int server_verify_login_msg(struct public_params *, struct server_secret *,
                            struct login_msg *);
int server_verify_reup_msg(struct public_params *, struct reup_msg *);
int server_verify_multi_msg(struct public_params *, struct server_secret *,
                            struct multi_msg *);

#endif /* __SERVER_H */
