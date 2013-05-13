/*
 * Copyright Michael Lee
 *
 * Anonymous subscription access check
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libhs.h>

#include <openssl/opensslconf.h> /* To see if OPENSSL_NO_ECDSA is defined */
#ifdef OPENSSL_NO_ECDSA
#error "You can't use openssl without EC"
#endif
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>

#include "defs.h"

typedef struct {
    struct hs_conn      *hs;
    EC_KEY              *sigkey;
    ngx_int_t            timeout;
    ngx_flag_t           auth_mode;
    ngx_flag_t           hs_enable;
    ngx_flag_t           enable_access;
    ngx_flag_t           enable_filter;
} ngx_http_auth_anon_loc_conf_t;

/* Initialization */
static void *ngx_http_auth_anon_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_anon_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_auth_anon_set_sig_pubkey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_anon_init(ngx_conf_t *cf);
static char *ngx_http_auth_anon_addr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_anon_update(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Handlers */
static ngx_int_t ngx_http_auth_anon_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_anon_filter_handler(ngx_http_request_t *r,
                                                   ngx_chain_t *in);
static ngx_int_t ngx_http_auth_anon_update_handler(ngx_http_request_t *r);

static ngx_http_output_body_filter_pt   ngx_http_next_body_filter;

static ngx_command_t  ngx_http_auth_anon_commands[] = {

    { ngx_string("auth_anon_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_anon_loc_conf_t, enable_access),
      NULL },

    { ngx_string("auth_anon_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_anon_loc_conf_t, enable_filter),
      NULL },

    { ngx_string("auth_anon_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_anon_loc_conf_t, auth_mode),
      NULL },

    { ngx_string("auth_anon_update"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_anon_update,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_anon_pubkey"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_anon_set_sig_pubkey,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_anon_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_anon_loc_conf_t, timeout),
      NULL },

    { ngx_string("auth_anon_addr"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE12,
      ngx_http_auth_anon_addr,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_auth_anon_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_anon_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_anon_create_loc_conf,   /* create location configuration */
    ngx_http_auth_anon_merge_loc_conf     /* merge location configuration */
};

ngx_module_t  ngx_http_auth_anon_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_anon_module_ctx,       /* module context */
    ngx_http_auth_anon_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

void
fprintf_hex_str(FILE *f, ngx_str_t *str)
{
    size_t i;
    for (i = 0; i < str->len; i++) {
        fprintf(f, "%02x", str->data[i]);
        if ((i+1) % 32 == 0)
            fprintf(f, "\n");
        else if ((i+1) % 4 == 0)
            fprintf(f, " ");
    }
}

static ngx_int_t
ngx_hash_and_verify(ngx_http_auth_anon_loc_conf_t *aalcf, u_char *buffer, size_t len, u_char *sigbuf)
{
    int rc = 0;
    u_char digest[HASH_DECODE_LEN] = {0};
    EVP_Digest(buffer, len, digest, 0, HASH_TYPE, NULL);
    if ((rc = !ECDSA_verify(0, digest, HASH_DECODE_LEN, sigbuf, SIG_DECODE_LEN, aalcf->sigkey)) != 0) {
        rc = -1;
    }
    return rc;
}

static ngx_int_t
ngx_http_auth_anon_access(ngx_http_request_t *r)
{
    ngx_http_auth_anon_loc_conf_t *aalcf;
    ngx_str_t                      key = (ngx_str_t)ngx_string("key");
    ngx_str_t                      k;
    u_char                         keybuf[HASH_DECODE_LEN + EPOCH_LEN];
    u_char                        *data = NULL;
    uint32_t                       len;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s", __func__);

    aalcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_anon_module);
    if (aalcf->hs_enable && !aalcf->hs) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "DHT is not initialized");
        goto out;
    }

    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                          &key, &key) == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "No included key");
        goto fail;
    }
    k.data = keybuf;
    ngx_decode_base64(&k, &key);

    if (aalcf->hs_enable) {
       if (hs_get(aalcf->hs, k.data + EPOCH_LEN - 4, &len, (void **)&data) <= 0) {
#if (BENCHMARK)
          r->connection->auth_timeout = time(NULL) + aalcf->timeout;
          goto out;
#else
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Not a valid session");
          goto fail;
#endif
       }
       r->connection->auth_timeout = time(NULL) + aalcf->timeout;
       free(data);
    }

 out:
    return NGX_OK;

 fail:
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_auth_anon_handler(ngx_http_request_t *r)
{
    ngx_http_auth_anon_loc_conf_t *aalcf;

    aalcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_anon_module);
    if (!aalcf->enable_access)
        /* Not enabled */
        goto out;

    if (ngx_http_auth_anon_access(r) != NGX_OK)
        goto fail;

 out:
        return NGX_OK;

 fail:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Authentication rejected");
    return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t
ngx_http_auth_anon_filter_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_auth_anon_loc_conf_t *aalcf;

    aalcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_anon_module);
    if (!aalcf->enable_filter)
        /* Not enabled */
        goto out;

    if (r->connection->auth_timeout > time(NULL))
        goto out;

    if (ngx_http_auth_anon_access(r) != NGX_OK)
        goto fail;

 out:
    return ngx_http_next_body_filter(r, in);

 fail:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Authentication timed out");
    ngx_http_finalize_request(r, NGX_ERROR);
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_auth_anon_update_handler(ngx_http_request_t *r)
{
    int           rc = NGX_ERROR;
    ngx_str_t     s, t, k;
    u_char        sigbuf[SIG_DECODE_LEN] = {0};
    u_char        tokbuf[HASH_DECODE_LEN + EPOCH_LEN] = {0};
    u_char        keybuf[HASH_DECODE_LEN + EPOCH_LEN] = {0};
    u_char        buffer[DATA_DECODE_LEN] = {0};
    uint32_t      len = 0;
    ngx_str_t     tok = (ngx_str_t)ngx_string("tok");
    ngx_str_t     sig = (ngx_str_t)ngx_string("sig");
    ngx_str_t     key = (ngx_str_t)ngx_string("key");
    int           reup = 1;
    ngx_http_auth_anon_loc_conf_t *aalcf;

    aalcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_anon_module);

    if (!(r->method & NGX_HTTP_HEAD)) {
        /* Only allow HEAD requests */
        return NGX_HTTP_NOT_ALLOWED;
    }

    r->headers_out.content_type = (ngx_str_t)ngx_string("text/plain");
    r->headers_out.status = NGX_HTTP_OK;

    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                          &key, &key) == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%s: Could not find 'key' in cookies", __func__);
        return NGX_HTTP_BAD_REQUEST;
    }
    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                          &sig, &sig) == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%s: Could not find 'sig' in cookies", __func__);
        return NGX_HTTP_BAD_REQUEST;
    }
    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                          &tok, &tok) == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "%s: Did not find 'tok' in cookies", __func__);
        reup = 0;
        tok = key;
    }

    /* Decode data */
    s.data = sigbuf;
    ngx_decode_base64(&s, &sig);

    k.data = keybuf;
    ngx_decode_base64(&k, &key);
    if (reup) {
        void *x = NULL;
        if (aalcf->hs_enable) {
           if ((rc = hs_get(aalcf->hs, keybuf + EPOCH_LEN - 4, &len, &x)) <= 0) {
              ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "%s: Not a valid key", __func__);
              return NGX_HTTP_BAD_REQUEST;
           }
           memcpy(buffer, x, len);
           if (x) free(x);
        }
    }

    t.data = tokbuf;
    ngx_decode_base64(&t, &tok);
    memcpy(buffer + len, tokbuf, t.len);
    len += t.len;

    /* Verify the message */
    if (((rc = ngx_hash_and_verify(aalcf, buffer, len, sigbuf)) != 0) &&
        !(aalcf->auth_mode && reup)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%s: Failed to verify signature", __func__);
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Do the update */
    if (aalcf->hs_enable) {
       if ((rc = hs_put(aalcf->hs, keybuf + EPOCH_LEN - 4, t.len, tokbuf)) <= 0) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "%s: Failed to store session", __func__);
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
       }
    }

    rc = ngx_http_send_header(r);

    return rc;
}

static ngx_int_t
ngx_http_auth_anon_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    /* Install the access control check */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_auth_anon_handler;

    /* Install the output filter check */
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_auth_anon_filter_handler;

    return NGX_OK;
}

static void *
ngx_http_auth_anon_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_anon_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_anon_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->hs = NGX_CONF_UNSET_PTR;
    conf->sigkey = NGX_CONF_UNSET_PTR;
    conf->hs_enable = NGX_CONF_UNSET;
    conf->auth_mode = NGX_CONF_UNSET;
    conf->enable_access = NGX_CONF_UNSET;
    conf->enable_filter = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_auth_anon_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_anon_loc_conf_t  *prev = parent;
    ngx_http_auth_anon_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->hs, prev->hs, NULL);
    ngx_conf_merge_ptr_value(conf->sigkey, prev->sigkey, NULL);
    ngx_conf_merge_value(conf->hs_enable,  prev->hs_enable,  0);
    ngx_conf_merge_value(conf->auth_mode,  prev->auth_mode,  0);
    ngx_conf_merge_value(conf->enable_access,  prev->enable_access,  0);
    ngx_conf_merge_value(conf->enable_filter,  prev->enable_filter,  0);
    ngx_conf_merge_sec_value(conf->timeout, prev->timeout, 60);

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_anon_addr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_anon_loc_conf_t *aalcf = conf;
    ngx_str_t                     *value;
    ngx_int_t                      port = 11211;

    if (aalcf->hs != NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    aalcf->hs = NULL;

    value = cf->args->elts;
    if (value[2].len) {
        port = strtod((char *)value[2].data, NULL);
    }
    aalcf->hs = hs_connect_str((char *)value[1].data, port);
    if (aalcf->hs == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to connect to hash server at %s:%d",
                           value[1].data, port);
        return NGX_CONF_ERROR;
    }

    aalcf->hs_enable = 1;

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_anon_set_sig_pubkey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *ret = NGX_CONF_OK;
    ngx_http_auth_anon_loc_conf_t *aalcf = conf;
    ngx_str_t                     *value;
    FILE                          *f;
    EC_POINT                      *pub = NULL;
    size_t                         alloc_len = 0;
    char                          *line;

    value = cf->args->elts;

    f = fopen((char *)value[1].data, "r");
    if (f == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Could not open public key file %s", value[1].data);
        return NGX_CONF_ERROR;
    }

    aalcf->sigkey = EC_KEY_new_by_curve_name(CURVE_NID);
    if (aalcf->sigkey == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Could not allocate private key for %s", value[1].data);
        ret = NGX_CONF_ERROR;
        goto out;
    }
    if (ECDSA_size(aalcf->sigkey) > SIG_DECODE_LEN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Key mismatch for %s", value[1].data);
        EC_KEY_free(aalcf->sigkey);
        ret = NGX_CONF_ERROR;
        goto out;
    }
    if (getline(&line, &alloc_len, f) == 0 ||
        (pub = EC_POINT_hex2point(EC_KEY_get0_group(aalcf->sigkey), line, pub, NULL)) == NULL ||
        EC_KEY_set_public_key(aalcf->sigkey, pub) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Could not load private key file %s", value[1].data);
        EC_KEY_free(aalcf->sigkey);
        ret = NGX_CONF_ERROR;
    }
    if (pub)
        EC_POINT_free(pub);
    if (line)
        free(line);
 out:
    fclose(f);

    return ret;
}

static char *
ngx_http_auth_anon_update(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t      *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_auth_anon_update_handler;

    return NGX_CONF_OK;
}
