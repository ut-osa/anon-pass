#ifndef _ANON_PASS_DEFS_H
#define _ANON_PASS_DEFS_H

#define PARAM_DECODE_LEN    RAW_PARAM_LEN
#define PARAM_ENCODE_LEN    ngx_base64_encoded_length(RAW_PARAM_LEN)
#define REG_MSG_DECODE_LEN  RAW_REG_MSG_LEN
#define REG_MSG_ENCODE_LEN  ngx_base64_encoded_length(RAW_REG_MSG_LEN)
#define REG_SIG_DECODE_LEN  RAW_REG_SIG_LEN
#define REG_SIG_ENCODE_LEN  ngx_base64_encoded_length(RAW_REG_SIG_LEN)
#define LOGIN_DECODE_LEN    RAW_LOGIN_LEN
#define LOGIN_ENCODE_LEN    ngx_base64_encoded_length(RAW_LOGIN_LEN)
#define REUP_DECODE_LEN     RAW_REUP_LEN
#define REUP_ENCODE_LEN     ngx_base64_encoded_length(RAW_REUP_LEN)
#define HASH_DECODE_LEN     20
#define HASH_ENCODE_LEN     ngx_base64_encoded_length(HASH_DECODE_LEN)
#define EPOCH_LEN           20
#define PRF_LEN             128
#define DATA_DECODE_LEN     (EPOCH_LEN + PRF_LEN)
#define SIG_DECODE_LEN      50 /* Observed between 46 and 48 bytes, told this is maximally 50 bytes */
#define SIG_ENCODE_LEN      ngx_base64_encoded_length(SIG_DECODE_LEN)
#define HASH_TYPE           EVP_sha1()
#define CURVE_NID           NID_secp160r1
#define AUTH_TOKEN_LEN      SIG_ENCODE_LEN


#endif
