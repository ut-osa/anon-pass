/*
 * Copyright (c) Michael Lee 2012-2013
 *
 * Anonymous subscription authentication and linking
 */

/* nginx related configuration */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libhs.h>

/* anon-pass related data structures */
#include <anon-pass/anon-pass.h>
#include <anon-pass/server.h>

#include <openssl/opensslconf.h> /* To see if OPENSSL_NO_ECDSA is defined */
#ifdef OPENSSL_NO_ECDSA
#error "You can't use openssl without EC"
#endif
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>

#include "bench.h"
#include "defs.h"

/* Data Type Definitions */
typedef struct {
    struct public_params *public;
    struct server_secret *server;
    /* Cached Data */
    ngx_str_t             pubkey;
    /* Shared storage */
    struct hs_conn       *hs;
    ngx_flag_t            hs_enable;
    /* App server update */
    ngx_int_t             timeout;
    EC_KEY               *sigkey;
    /* Debug information */
    ngx_flag_t            enable;
} ngx_http_anon_pass_loc_conf_t;

typedef enum {
    ANON_PASS_UNDEFINED,
    ANON_PASS_PARAMS,
    ANON_PASS_REGISTER,
    ANON_PASS_LOGIN,
    ANON_PASS_REUP,
} ngx_anon_pass_req_type;

#define ANON_OK           (ngx_str_t){2, (u_char *)"ok"}
#define ANON_FAIL         (ngx_str_t){4, (u_char *)"fail"}
#define ANON_BAD_REQUEST  (ngx_str_t){0, (void *)NGX_HTTP_BAD_REQUEST}
#define ANON_UNAUTHORIZED (ngx_str_t){0, (void *)NGX_HTTP_UNAUTHORIZED}
#define ANON_ERROR        (ngx_str_t){0, (void *)NGX_HTTP_INTERNAL_SERVER_ERROR}

/* Forward Declarations */
static char *ngx_http_anon_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_anon_pass_addr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_anon_pass_request_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_anon_pass_set_sig_privkey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_anon_pass_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_anon_pass_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_anon_pass_init(ngx_conf_t *cf, ngx_http_anon_pass_loc_conf_t *lcf);
static void ngx_http_anon_pass_exit(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_anon_pass_commands[] = {

    { ngx_string("anon_pass"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_anon_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("anon_pass_addr"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE12,
      ngx_http_anon_pass_addr,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("anon_pass_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_anon_pass_loc_conf_t, timeout),
      NULL },

    { ngx_string("anon_pass_privkey"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_anon_pass_set_sig_privkey,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("anon_pass_request_log"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_anon_pass_request_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_anon_pass_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_anon_pass_create_loc_conf, /* create location configuration */
    ngx_http_anon_pass_merge_loc_conf   /* merge location configuration */
};

ngx_module_t  ngx_http_anon_pass_module = {
    NGX_MODULE_V1,
    &ngx_http_anon_pass_module_ctx, /* module context */
    ngx_http_anon_pass_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    ngx_http_anon_pass_exit,       /* exit master */
    NGX_MODULE_V1_PADDING
};

void
fprintf_str(FILE *f, ngx_str_t *str)
{
    size_t i;
    for (i = 0; i < str->len; i++) {
        fprintf(f, "%c", str->data[i]);
    }
    fprintf(f, "\n");
}

static inline int
ngx_str_endswith(ngx_str_t *s1, char *s2)
{
    return ngx_strncmp(s1->data + s1->len - strlen((char *)s2), s2, strlen((char *)s2));
}

static ngx_int_t
ngx_str_unwrap_base64(ngx_http_request_t *r, ngx_str_t *data, element_t *els[])
{
    ngx_str_t tmp;
    ngx_int_t i = 0;
    off_t off = 0;

    if (!data)
        return 0;

    tmp.data = ngx_palloc(r->pool, ngx_base64_decoded_length(data->len));
    if (tmp.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory.");
        return -1;
    }

    ngx_decode_base64(&tmp, data);
    for (i = 0; *els[i]; i++) {
        off += element_from_bytes(*els[i], tmp.data + off);
    }

    ngx_pfree(r->pool, tmp.data);
    return i;
}

static ngx_int_t
ngx_str_wrap_base64(ngx_http_request_t *r, ngx_str_t *data, element_t *els[])
{
    ngx_str_t tmp;
    ngx_int_t i = 0;
    off_t off = 0;

    if (!data)
        return 0;

    tmp = (ngx_str_t){ngx_base64_decoded_length(data->len),
                      ngx_palloc(r->pool, ngx_base64_decoded_length(data->len))};
    if (tmp.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory.");
        return -1;
    }

    for (i = 0; *els[i]; i++) {
        off += element_to_bytes(tmp.data + off, *els[i]);
    }
    ngx_encode_base64(data, &tmp);

    ngx_pfree(r->pool, tmp.data);
    return i;
}

static ngx_int_t
ngx_hash_and_sign(ngx_http_anon_pass_loc_conf_t *aplcf, u_char *buffer, size_t len, u_char *sigbuf)
{
    int rc = 0;
    u_char digest[HASH_DECODE_LEN] = {0};
    unsigned int siglen = 0;
    EVP_Digest(buffer, len, digest, 0, HASH_TYPE, NULL);
    if ((rc = !ECDSA_sign(0, digest, HASH_DECODE_LEN, sigbuf, &siglen, aplcf->sigkey)) != 0) {
        rc = -1;
    }
    if (siglen > SIG_DECODE_LEN) {
        fprintf(stderr, "Unexpected sig length %d - returned sig length %d\n", SIG_DECODE_LEN, siglen);
    }
    return rc;
}

extern void fprintf_hex_str(FILE *f, ngx_str_t *str);
static ngx_int_t
ngx_http_store_token(ngx_http_request_t *r, element_t tok,
                     element_t epoch, ngx_str_t *out)
{
    int       rc;
    ngx_str_t s, t;
    off_t     off = 0;
    u_char    sig[SIG_ENCODE_LEN] = {0};
    u_char    sigbuf[SIG_DECODE_LEN] = {0};
    u_char   *curr_hash = NULL;
    u_char    buffer[SIG_ENCODE_LEN] = {0};
    u_char   *ptr;
    ngx_http_anon_pass_loc_conf_t  *aplcf;
#ifdef BENCH_LOG
    struct timeval start = {0,0}, end = {0,0};
#endif

    aplcf = ngx_http_get_module_loc_conf(r, ngx_http_anon_pass_module);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", __func__);

    /* Form the message */
    off = element_to_bytes(buffer, epoch);
    curr_hash = buffer + off;
    hash_element(curr_hash, tok);
    off += HASH_DECODE_LEN;

    /* Check the login */
#ifdef BENCH_LOG
    gettimeofday(&start, NULL);
#endif
    if (aplcf->hs_enable) {
#if (DEBUG)
       struct timeval now;
       ngx_str_t tmp = (ngx_str_t){20, curr_hash};
       gettimeofday(&now, NULL);
       fprintf(stderr, "[%02ld:%02ld.%02ld] ",
               (now.tv_sec / 3600) % 24, (now.tv_sec / 60) % 60, now.tv_sec % 60);
       fprintf_hex_str(stderr, &tmp);
       fprintf(stderr, "\n");
#endif
       rc = hs_login(aplcf->hs, curr_hash);
       if (rc != 1) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "%s: Error - failed to login %d", __func__, rc);
          rc = -1;
          goto out;
       }
    }
#ifdef BENCH_LOG
    gettimeofday(&end, NULL);
    log_entries[cur_entry].hs = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

    /* Sign the message */
#ifdef BENCH_LOG
    gettimeofday(&start, NULL);
#endif
    if ((rc = ngx_hash_and_sign(aplcf, buffer, off, sigbuf)) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: Signature failed %d",
                      __func__, rc);
        goto out;
    }
#ifdef BENCH_LOG
    gettimeofday(&end, NULL);
    log_entries[cur_entry].sig = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

    s = (ngx_str_t){SIG_ENCODE_LEN, sig};
    t = (ngx_str_t){SIG_DECODE_LEN, sigbuf};
    ngx_encode_base64(&s, &t);

    ptr = out->data;
    ptr = ngx_copy(ptr, "sig=", sizeof("sig=") - 1);
    ptr = ngx_copy(ptr, sig, SIG_ENCODE_LEN);
    *ptr++ = ';';
    out->len = ptr - out->data;

 out:
    return rc;
}

static ngx_int_t
ngx_http_link_token(ngx_http_request_t *r, element_t curr_tok, element_t next_tok,
                    element_t epoch, ngx_str_t *out)
{
    int       rc;
    ngx_str_t s, t;
    off_t     off = 0;
    u_char    sig[SIG_ENCODE_LEN] = {0};
    u_char    sigbuf[SIG_DECODE_LEN] = {0};
    u_char   *curr_hash = NULL;
    u_char   *next_hash = NULL;
    u_char    buffer[SIG_ENCODE_LEN] = {0};
    u_char   *ptr;
    ngx_http_anon_pass_loc_conf_t  *aplcf;
#ifdef BENCH_RUP
    struct timeval start = {0,0}, end = {0,0};
#endif

    aplcf = ngx_http_get_module_loc_conf(r, ngx_http_anon_pass_module);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", __func__);

    /* Form the message */
    off = element_to_bytes(buffer, epoch);
    curr_hash = buffer + off;
    hash_element(curr_hash, curr_tok);
    off += HASH_DECODE_LEN;
    element_add_ui(epoch, epoch, 1);
    off += element_to_bytes(buffer + off, epoch);
    next_hash = buffer + off;
    hash_element(next_hash, next_tok);
    off += HASH_DECODE_LEN;

    /* Link the message */
#ifdef BENCH_RUP
    gettimeofday(&start, NULL);
#endif
    if (aplcf->hs_enable) {
#if (DEBUG)
       struct timeval now;
       ngx_str_t tmp = (ngx_str_t){20, curr_hash};
       gettimeofday(&now, NULL);
       fprintf(stderr, "[%02ld:%02ld.%02ld] ",
               (now.tv_sec / 3600) % 24, (now.tv_sec / 60) % 60, now.tv_sec % 60);
       fprintf_hex_str(stderr, &tmp);
       fprintf(stderr, " -> ");
       tmp.data = next_hash;
       fprintf_hex_str(stderr, &tmp);
       fprintf(stderr, "\n");
#endif
       rc = hs_link(aplcf->hs, curr_hash, next_hash);
       if (rc != 1) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "%s: Error - failed to link %d", __func__, rc);
          rc = -1;
          goto out;
       }
    }
#ifdef BENCH_RUP
    gettimeofday(&end, NULL);
    log_entries[cur_entry].hs = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

    /* Sign the message */
#ifdef BENCH_RUP
    gettimeofday(&start, NULL);
#endif
    if ((rc = ngx_hash_and_sign(aplcf, buffer, off, sigbuf)) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: Signature failed %d",
                      __func__, rc);
        goto out;
    }
#ifdef BENCH_RUP
    gettimeofday(&end, NULL);
    log_entries[cur_entry].sig = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

    s = (ngx_str_t){SIG_ENCODE_LEN, sig};
    t = (ngx_str_t){SIG_DECODE_LEN, sigbuf};
    ngx_encode_base64(&s, &t);

    ptr = out->data;
    ptr = ngx_copy(ptr, "sig=", sizeof("sig=") - 1);
    ptr = ngx_copy(ptr, sig, SIG_ENCODE_LEN);
    *ptr++ = ';';
    out->len = ptr - out->data;

 out:
    return rc;
}

static ngx_str_t
ngx_http_anon_pass_params(ngx_http_request_t *r)
{
    ngx_http_anon_pass_loc_conf_t  *aplcf;
    aplcf = ngx_http_get_module_loc_conf(r, ngx_http_anon_pass_module);
    return (ngx_str_t){aplcf->pubkey.len, ngx_pstrdup(r->pool, &aplcf->pubkey)};
}

static ngx_str_t
ngx_http_anon_pass_register(ngx_http_request_t *r, ngx_str_t *data)
{
    ngx_str_t            ret;
    struct register_msg  msg;
    struct register_sig  sig;
    ngx_http_anon_pass_loc_conf_t  *aplcf;

#ifdef BENCH_REG
    struct timeval start = {0,0}, end = {0,0};
#endif

    aplcf = ngx_http_get_module_loc_conf(r, ngx_http_anon_pass_module);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", __func__);


    /* Data unwrap */
    if (data->len != REG_MSG_ENCODE_LEN) {
        return ANON_BAD_REQUEST;
    }

    reg_msg_init(aplcf->public, &msg);
    if (ngx_str_unwrap_base64(r, data, (element_t *[]){
                &msg.M, &msg.R, &msg.rg, &msg.rZ, NULL}) <= 0) {
        return ANON_ERROR;
    }

    /* Do the actual work */
#ifdef BENCH_REG
    gettimeofday(&start, NULL);
#endif
    if (!server_verify_reg_msg(aplcf->public, aplcf->server, &msg)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to verify register.");
        return ANON_BAD_REQUEST;
    }
#ifdef BENCH_REG
    gettimeofday(&end, NULL);
    log_entries[cur_entry].ver = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

#ifdef BENCH_REG
    gettimeofday(&start, NULL);
#endif
    server_sign_reg_msg(aplcf->public, aplcf->server, &msg, &sig);
#ifdef BENCH_REG
    gettimeofday(&end, NULL);
    log_entries[cur_entry].sig = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

    /* Data wrap */
    ret = (ngx_str_t){ngx_base64_encoded_length(512),
                      ngx_pcalloc(r->pool, ngx_base64_encoded_length(512))};
    if (ret.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory.");
        ret = ANON_ERROR;
        goto out;
    }
    if (ngx_str_wrap_base64(r, &ret, (element_t *[]){
                &sig.A, &sig.B, &sig.ZB, &sig.C, NULL}) <= 0) {
        ret = ANON_ERROR;
        goto out;
    }

 out:
    reg_msg_clear(&msg);
    reg_sig_clear(&sig, 0);
    return ret;
}

static ngx_str_t
ngx_http_anon_pass_login(ngx_http_request_t *r, ngx_str_t *data, ngx_str_t *out)
{
    struct login_msg               msg;
    ngx_str_t                      ret;
    ngx_http_anon_pass_loc_conf_t *aplcf;

#ifdef BENCH_LOG
    struct timeval start = {0,0}, end = {0,0};
#endif

    aplcf = ngx_http_get_module_loc_conf(r, ngx_http_anon_pass_module);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", __func__);

    /* Data unwrap */
    if (data->len != LOGIN_ENCODE_LEN) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Empty request");
        return ANON_BAD_REQUEST;
    }
    login_msg_init(aplcf->public, &msg);
    if (ngx_str_unwrap_base64(r, data, (element_t *[]){
                &msg.A, &msg.B, &msg.ZB, &msg.C,
                    &msg.d, &msg.r, &msg.r2,
                    &msg.R1, &msg.Yt, &msg.R2, &msg.t,NULL}) <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory");
        return ANON_ERROR;
    }

    /* Do the actual work */
#ifdef BENCH_LOG
    gettimeofday(&start, NULL);
#endif
    if (!server_verify_login_msg(aplcf->public, aplcf->server, &msg)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to verify login.");
        ret = ANON_BAD_REQUEST;
        goto out;
    }
#ifdef BENCH_LOG
    gettimeofday(&end, NULL);
    log_entries[cur_entry].ver = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

    if (ngx_http_store_token(r, msg.Yt, msg.t, out) < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Double login detected");
        ret = ANON_UNAUTHORIZED;
        goto out;
    }

    /* Data Wrap */
    ret = ANON_OK;

 out:
    login_msg_clear(&msg);
    return ret;
}

static ngx_str_t
ngx_http_anon_pass_reup(ngx_http_request_t *r, ngx_str_t *data, ngx_str_t *out)
{
    ngx_str_t     ret;
    struct reup_msg msg;
    ngx_http_anon_pass_loc_conf_t  *aplcf;

#ifdef BENCH_RUP
    struct timeval start = {0,0}, end = {0,0};
#endif

    aplcf = ngx_http_get_module_loc_conf(r, ngx_http_anon_pass_module);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", __func__);

    /* Data unwrap */
    if (data->len != REUP_ENCODE_LEN) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Empty request");
        return ANON_BAD_REQUEST;
    }
    reup_msg_init(aplcf->public, &msg);
    if (ngx_str_unwrap_base64(r, data, (element_t *[]){
                &msg.Yt, &msg.Rt, &msg.Ys, &msg.Rs,
                    &msg.a, &msg.t, NULL}) <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory");
        ret = ANON_ERROR;
        goto out;
    }

    /* Do the actual work */
#ifdef BENCH_RUP
    gettimeofday(&start, NULL);
#endif
    if (!server_verify_reup_msg(aplcf->public, &msg)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to verify reup.");
        ret = ANON_BAD_REQUEST;
        goto out;
    }
#ifdef BENCH_RUP
    gettimeofday(&end, NULL);
    log_entries[cur_entry].ver = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
#endif

    if (ngx_http_link_token(r, msg.Yt, msg.Ys, msg.t, out) < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid reup request");
        ret = ANON_UNAUTHORIZED;
        goto out;
    }

    /* Data Wrap */
    ret = ANON_OK;

 out:
    reup_msg_clear(&msg);
    return ret;
}

static ngx_str_t
ngx_http_anon_pass_default(ngx_http_request_t *r)
{
    /* Well, this is actually an error, yes? */
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", __func__);
    return ANON_FAIL;
}

static ngx_int_t
ngx_http_anon_pass_handler(ngx_http_request_t *r)
{
    ngx_int_t     rc = NGX_ERROR;
    /* Arguments */
    ngx_anon_pass_req_type type = ANON_PASS_UNDEFINED;
    ngx_str_t     arg_data = (ngx_str_t)ngx_string("data");
    /* Return values */
    ngx_str_t     retval   = (ngx_str_t)ngx_string("");
    ngx_str_t     out_data = (ngx_str_t)ngx_null_string;
    u_char        out_buf[AUTH_TOKEN_LEN + sizeof("sig=;") - 1];
    ngx_buf_t    *buffer;
    ngx_chain_t   out;

#ifdef BENCH
    struct timeval start = {0,0}, end = {0,0};
    gettimeofday(&start, NULL);
#endif

    /* Rudimentary error checking */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;
    if (r->headers_in.if_modified_since)
        return NGX_HTTP_NOT_MODIFIED;

    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                          &arg_data, &arg_data) == NGX_DECLINED) {
        arg_data = (ngx_str_t)ngx_null_string;
    }

    /* Parse the request */
    if (ngx_str_endswith(&r->uri, "/params") == 0) {
        type = ANON_PASS_PARAMS;
    } else if (ngx_str_endswith(&r->uri, "/register") == 0 &&
               arg_data.len == REG_MSG_ENCODE_LEN) {
        type = ANON_PASS_REGISTER;
    } else if (ngx_str_endswith(&r->uri, "/login") == 0 &&
               arg_data.len == LOGIN_ENCODE_LEN) {
        type = ANON_PASS_LOGIN;
    } else if (ngx_str_endswith(&r->uri, "/reup") == 0 &&
               arg_data.len == REUP_ENCODE_LEN) {
        type = ANON_PASS_REUP;
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "uri: %V, args: %V, len %d", &r->uri, &r->args, r->args.len);
    }
#ifdef REQ_BENCH
    switch (type) {
    case ANON_PASS_REGISTER:
       request_count[reg] ++;
       break;
    case ANON_PASS_LOGIN:
       request_count[log] ++;
       break;
    case ANON_PASS_REUP:
       request_count[rup] ++;
       break;
    default:
       break;
    }
#endif

    /* Setup the header */
    r->headers_out.content_type = (ngx_str_t)ngx_string("text/plain");
    r->headers_out.status = NGX_HTTP_OK;

    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
            goto err;
    }

    switch (type) {
    case ANON_PASS_PARAMS:
        retval = ngx_http_anon_pass_params(r);
        break;
    case ANON_PASS_REGISTER:
        retval = ngx_http_anon_pass_register(r, &arg_data);
        break;
    case ANON_PASS_LOGIN:
        out_data.data = out_buf;
        retval = ngx_http_anon_pass_login(r, &arg_data, &out_data);
        if (retval.len == 0) {
            switch ((uint64_t)retval.data) {
            case NGX_HTTP_BAD_REQUEST:
                retval = (ngx_str_t){32, ngx_palloc(r->pool, 32)};
                retval.len = snprintf((char *)retval.data, 32, "fail (request): %ld", time(NULL));
                break;
            case NGX_HTTP_UNAUTHORIZED:
                retval = (ngx_str_t){32, ngx_palloc(r->pool, 32)};
                retval.len = snprintf((char *)retval.data, 32, "fail (access): %ld", time(NULL));
                break;
            default:
                retval = ANON_ERROR;
            }
            if (retval.len >= 32) {
                fprintf(stderr, "Trucation error\n");
                ngx_free(retval.data);
                retval = ANON_ERROR;
            }
        }
        break;
    case ANON_PASS_REUP:
        out_data.data = out_buf;
        retval = ngx_http_anon_pass_reup(r, &arg_data, &out_data);
        break;
    default:
        retval = ngx_http_anon_pass_default(r);
        break;
    }

    if (!retval.len) {
        /* Empty message body */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error: %d",
                      (ngx_int_t)retval.data);
        rc = (ngx_int_t)retval.data;
        goto err;
    }

    buffer = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buffer == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Failed to allocate response buffer.");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto err;
    }

    switch (type) {
    case ANON_PASS_REUP:
    case ANON_PASS_LOGIN:
        if (out_data.len) {
            ngx_table_elt_t *h;
            h = ngx_list_push(&r->headers_out.headers);
            if (h == NULL) {
                rc = NGX_ERROR;
                goto err;
            }
            h->hash = 1;
            h->key = (ngx_str_t)ngx_string("Set-Cookie");
            h->value = out_data;
        }
        break;
    default:
        break;
    }

    out.buf = buffer;
    out.next = NULL;

    buffer->pos = retval.data;
    buffer->last = retval.data + retval.len;

    buffer->memory = 1;
    buffer->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        goto err;

#ifdef BENCH
    gettimeofday(&end, NULL);
#if (defined BENCH_REG)
    if (type == ANON_PASS_REGISTER) {
        log_entries[cur_entry].tot = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    }
#elif (defined BENCH_LOG)
    if (type == ANON_PASS_LOGIN) {
        log_entries[cur_entry].tot = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    }
#elif (defined BENCH_RUP)
    if (type == ANON_PASS_REUP) {
        log_entries[cur_entry].tot = (unsigned short)1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    }
#endif
    cur_entry++;
    if (cur_entry == MAX_RECORD) {
        FILE *f;
        char fname[128] = {0};
        int i;
        snprintf(fname, 128, "%s.%d.log", request_log_name, getpid());
        f = fopen(fname, "a");
        if (f) {
            for (i = 50; i < MAX_RECORD; i++) {
                fprintf(f, "%d %d %d %d\n", log_entries[i].tot, log_entries[i].ver, log_entries[i].sig, log_entries[i].hs);
            }
            fflush(f);
            fclose(f);
        } else {
            fprintf(stderr, "Couldn't open file...\n");
            for (i = 50; i < MAX_RECORD; i++) {
                fprintf(stderr, "%d %d %d %d\n", log_entries[i].tot, log_entries[i].ver, log_entries[i].sig, log_entries[i].hs);
            }
        }
        cur_entry = 0;
    }
#endif
#ifdef REQ_BENCH
    switch (type) {
    case ANON_PASS_REGISTER:
       request_pass[reg] ++;
       break;
    case ANON_PASS_LOGIN:
       request_pass[log] ++;
       break;
    case ANON_PASS_REUP:
       request_pass[rup] ++;
       break;
    default:
       break;
    }
    if (request_log) {
        long stamp = time(NULL);
        int i;
        if (stamp > last_bench) {
            for (i = 0; i < MAX_TIMER; i ++) {
                if (!request_count[i])
                    continue;
                fprintf(request_log, "[%ld]%s: [count] %ld\t[pass] %ld\n",
                        stamp, request_name[i], request_count[i], request_pass[i]);
                request_count[i] = 0;
                request_pass[i] = 0;
                fflush(request_log);
            }
            last_bench = stamp;
        }
    }
#endif

    return ngx_http_output_filter(r, &out);
 err:
#ifdef REQ_BENCH
    if (request_log) {
        long stamp = time(NULL);
        if (stamp > last_bench) {
            int i;
            for (i = 0; i < MAX_TIMER; i ++) {
                if (!request_count[i])
                    continue;
                fprintf(request_log, "[%ld]%s: [count] %ld\t[pass] %ld\n",
                        stamp, request_name[i], request_count[i], request_pass[i]);
                request_count[i] = 0;
                request_pass[i] = 0;
                fflush(request_log);
            }
            last_bench = stamp;
        }
    }
#endif
    return rc;
}

static char *
ngx_http_anon_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_anon_pass_loc_conf_t *aplcf = conf;
    ngx_str_t                     *value;

    if (aplcf->public != NGX_CONF_UNSET_PTR || aplcf->server != NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_anon_pass_handler;

    aplcf->enable = 1;

    value = cf->args->elts;

    aplcf->public = ngx_pcalloc(cf->pool, sizeof(*aplcf->public));
    aplcf->server = ngx_pcalloc(cf->pool, sizeof(*aplcf->server));
    pairing_init(aplcf->public->p, fopen((char *)value[1].data, "r"));
    server_init(aplcf->public, aplcf->server, fopen((char *)value[2].data, "a+"),
                fopen((char *)value[3].data, "a+"));

    return NGX_CONF_OK;
}

static char *
ngx_http_anon_pass_addr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_anon_pass_loc_conf_t *aplcf = conf;
    ngx_str_t                     *value;
    ngx_int_t                      port = 6666;

    if (aplcf->hs != NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    aplcf->hs = NULL;

    value = cf->args->elts;
    if (value[2].len) {
        port = strtod((char *)value[2].data, NULL);
    }
    aplcf->hs = hs_connect_str((char *)value[1].data, port);
    if (aplcf->hs == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to connect to hash server at %s:%d",
                           value[1].data, port);
        return NGX_CONF_ERROR;
    }

    aplcf->hs_enable = 1;

    return NGX_CONF_OK;
}

static char *
ngx_http_anon_pass_request_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#ifdef BENCH
    ngx_str_t                     *value;
    value = cf->args->elts;
    strcpy(request_log_name, (char *)value[1].data);
#endif
#ifdef REQ_BENCH
    ngx_str_t                     *value;
    value = cf->args->elts;
    request_log = fopen((char *)value[1].data, "a");
#endif

    return NGX_CONF_OK;
}

static char *
ngx_http_anon_pass_set_sig_privkey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *ret = NGX_CONF_OK;
    ngx_http_anon_pass_loc_conf_t *aplcf = conf;
    ngx_str_t                     *value;
    FILE                          *f;
    BIGNUM   *priv = NULL;
    EC_POINT *pub  = NULL;
    size_t alloc_len = 0;
    char *line;

    value = cf->args->elts;

    f = fopen((char *)value[1].data, "r");
    if (f == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Could not open private key file %s", value[1].data);
        return NGX_CONF_ERROR;
    }

    aplcf->sigkey = EC_KEY_new_by_curve_name(CURVE_NID);
    if (aplcf->sigkey == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Could not allocate private key for %s", value[1].data);
        ret = NGX_CONF_ERROR;
        goto out;
    }
    if (ECDSA_size(aplcf->sigkey) > SIG_DECODE_LEN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Key mismatch for %s", value[1].data);
        EC_KEY_free(aplcf->sigkey);
        ret = NGX_CONF_ERROR;
        goto out;
    }
    /* Signing requires both the public and private keys */
    if (getline(&line, &alloc_len, f) == 0 ||
        (pub = EC_POINT_hex2point(EC_KEY_get0_group(aplcf->sigkey), line, pub, NULL)) == NULL ||
        EC_KEY_set_public_key(aplcf->sigkey, pub) == 0 ||
        getline(&line, &alloc_len, f) == 0 ||
        BN_hex2bn(&priv, line) == 0 ||
        EC_KEY_set_private_key(aplcf->sigkey, priv) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Could not load private key file %s", value[1].data);
        EC_KEY_free(aplcf->sigkey);
        ret = NGX_CONF_ERROR;
    }
    if (priv)
        BN_free(priv);
    if (pub)
        EC_POINT_free(pub);
    if (line)
        free(line);
    EC_KEY_precompute_mult(aplcf->sigkey, NULL);
 out:
    fclose(f);
    return ret;
}

static ngx_int_t
ngx_http_anon_pass_init(ngx_conf_t *cf, ngx_http_anon_pass_loc_conf_t *lcf)
{
    ngx_str_t tmp;
    off_t     off = 0;

    /* Cache the public key */
    tmp.data = ngx_pcalloc(cf->pool, PARAM_DECODE_LEN);
    lcf->pubkey.data = ngx_pcalloc(cf->pool, PARAM_ENCODE_LEN);
    off += element_to_bytes(tmp.data + off, lcf->public->g);
    off += element_to_bytes(tmp.data + off, lcf->public->X);
    off += element_to_bytes(tmp.data + off, lcf->public->Y);
    off += element_to_bytes(tmp.data + off, lcf->public->Z);
    off += element_to_bytes(tmp.data + off, lcf->public->W);
    tmp.len = off;
    ngx_encode_base64(&lcf->pubkey, &tmp);
    ngx_pfree(cf->pool, tmp.data);

    return NGX_OK;
}

static void *
ngx_http_anon_pass_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_anon_pass_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_anon_pass_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->public = NGX_CONF_UNSET_PTR;
    conf->server = NGX_CONF_UNSET_PTR;

    conf->hs = NGX_CONF_UNSET_PTR;
    conf->hs_enable = NGX_CONF_UNSET;
    conf->sigkey = NGX_CONF_UNSET_PTR;

    conf->timeout = NGX_CONF_UNSET;
    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_anon_pass_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_anon_pass_loc_conf_t *prev = parent;
    ngx_http_anon_pass_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->public, prev->public, NULL);
    ngx_conf_merge_ptr_value(conf->server, prev->server, NULL);

    ngx_conf_merge_str_value(conf->pubkey, prev->pubkey, NULL);

    ngx_conf_merge_ptr_value(conf->hs, prev->hs, NULL);
    ngx_conf_merge_value(conf->hs_enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->sigkey, prev->sigkey, NULL);

    ngx_conf_merge_sec_value(conf->timeout, prev->timeout, 60);
    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if(conf->enable)
        ngx_http_anon_pass_init(cf, conf);

    return NGX_CONF_OK;
}

static void
ngx_http_anon_pass_exit(ngx_cycle_t *cycle)
{
#ifdef REQ_BENCH
   if (request_log) {
      fflush(request_log);
      fclose(request_log);
   }
#endif
}
