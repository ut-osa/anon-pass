#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sys/time.h>

#include <openssl/opensslconf.h> /* To see if OPENSSL_NO_ECDSA is defined */
#ifdef OPENSSL_NO_ECDSA
#error "Error"
#endif

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>

#define CURVE_ID NID_secp160r1
/* #define CURVE_ID NID_secp192k1 */

#define NORMAL_TEST

#define MAX_HASH_LEN 128
#define N_ITERS 256
#define quitif(cond, msg...) if ( (cond) ) {fprintf(stderr, msg); exit(-1);} else

static const char rnd_seed[] = "string to make the random number generator "
    "think it has entropy";

static int hash_len[] = {1, 20, 32, 64, 128, 0};

int main(int argc, char *argv[])
{
    int fd = open("/dev/random", 0);
    uint8_t seed[256] = {0};
    size_t sz = 0;
    FILE *f = NULL;
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    ERR_load_crypto_strings();

    EC_builtin_curve *curves = NULL;
    size_t            crv_len = 0, n = 0, i;
    EC_KEY           *eckey = NULL, *priv_eckey = NULL, *pub_eckey = NULL;
    char             *pub_key, *priv_key;
    BIGNUM           *priv = NULL;
    EC_POINT         *pub = NULL;
    EC_GROUP         *group;
    unsigned char     digest[MAX_HASH_LEN] = {0}, priv_digest[MAX_HASH_LEN];
    unsigned char     blocks[N_ITERS * MAX_HASH_LEN];
    unsigned char    *signature = NULL;
    unsigned char    *sigs = NULL;
    unsigned int      sig_len;
    int               nid, ret =  0;
    int              *len = hash_len;
    unsigned int      dgst_len;

    if (argc > 1) {
       f = fopen(argv[1], "r");
    } else {
       sz = read(fd, seed, 256);
       printf("Only read %ld bytes\n", sz);
       RAND_seed(seed, sz);
    }
    close(fd);

    EVP_Digest(digest, MAX_HASH_LEN, digest, &dgst_len, EVP_sha1(), NULL);
    for (i = 0; i < dgst_len; i++) {
       fprintf(stderr, "%02x", digest[i]);
    }
    fprintf(stderr, "\n");

    eckey = EC_KEY_new_by_curve_name(CURVE_ID);
    if (f) {
       sz = 0;
       sz = getline(&pub_key, &sz, f);
       pub_key[sz-1] = '\0';
       printf("%s\n", pub_key);
       sz = 0;
       sz = getline(&priv_key, &sz, f);
       priv_key[sz-1] = '\0';
       printf("%s\n", priv_key);
       BN_hex2bn(&priv, priv_key);
       EC_KEY_set_private_key(eckey, priv);
       pub = EC_POINT_hex2point(EC_KEY_get0_group(eckey), pub_key, pub, NULL);
       EC_KEY_set_public_key(eckey, pub);
       BN_free(priv);
       EC_POINT_free(pub);
       free(pub_key);
       free(priv_key);
       pub_key = priv_key = priv = pub = NULL;
    } else {
       EC_KEY_generate_key(eckey);
    }

    pub_key = EC_POINT_point2hex(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey), 2, NULL);
    printf("%s\n", pub_key);
    priv_key = BN_bn2hex(EC_KEY_get0_private_key(eckey));
    printf("%s\n", priv_key);
    priv_eckey = EC_KEY_new_by_curve_name(CURVE_ID);
    pub_eckey  = EC_KEY_new_by_curve_name(CURVE_ID);
    BN_hex2bn(&priv, priv_key);
    EC_KEY_set_private_key(priv_eckey, priv);
    pub = EC_POINT_hex2point(EC_KEY_get0_group(eckey), pub_key, pub, NULL);
    EC_KEY_set_public_key(pub_eckey, pub);
    EC_KEY_set_public_key(priv_eckey, pub);
    free(pub_key);
    free(priv_key);
    BN_free(priv);
    EC_POINT_free(pub);

    pub_key = EC_POINT_point2hex(EC_KEY_get0_group(pub_eckey), EC_KEY_get0_public_key(priv_eckey), 2, NULL);
    printf("%s\n", pub_key);
    priv_key = BN_bn2hex(EC_KEY_get0_private_key(priv_eckey));
    printf("%s\n", priv_key);
    free(pub_key);
    free(priv_key);

    sig_len = ECDSA_size(eckey);
    quitif ((signature = OPENSSL_malloc(sig_len)) == NULL, " malloc error\n");
    quitif(!ECDSA_sign(0, digest, MAX_HASH_LEN, signature, &sig_len, eckey), " failed\n");
    quitif (ECDSA_verify(0, digest, MAX_HASH_LEN, signature, sig_len, eckey) != 1, " failed (verify)\n");
    quitif(!ECDSA_sign(0, digest, MAX_HASH_LEN, signature, &sig_len, priv_eckey), " failed\n");
    quitif (ECDSA_verify(0, digest, MAX_HASH_LEN, signature, sig_len, pub_eckey) != 1, " failed (other verify)\n");

    OPENSSL_free(signature);
    EC_KEY_free(priv_eckey);
    EC_KEY_free(pub_eckey);
    EC_KEY_free(eckey);
    printf("%d\n", sig_len);

    crv_len = EC_get_builtin_curves(NULL, 0);
    curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * crv_len);
    quitif(curves == NULL, "malloc error\n");

    quitif(!EC_get_builtin_curves(curves, crv_len), "unable to get internal curves");

 loop:
    fprintf(stderr, "Hash size  %d\n", *len);
    for (n = 0; n < crv_len; n++) {
        unsigned char dirt, offset;
        nid = curves[n].nid;
        if (nid == NID_ipsec4)
            continue;
        if (nid < NID_secp160k1 || nid >= NID_secp256k1)
           continue;

        quitif((eckey = EC_KEY_new()) == NULL, " failed (key alloc)\n");
        quitif((group = EC_GROUP_new_by_curve_name(nid)) ==  NULL, " failed (curve alloc)\n");
        quitif(EC_KEY_set_group(eckey, group) == 0, " failed (set group)\n");
        EC_GROUP_free(group);
        if (EC_GROUP_get_degree(EC_KEY_get0_group(eckey)) < 160) {
            EC_KEY_free(eckey);
            eckey = NULL;
            continue;
        }
        fprintf(stderr, "[%d] %s", nid, OBJ_nid2sn(nid));
        quitif(!EC_KEY_generate_key(eckey), " failed (key gen)\n");

#ifdef NORMAL_TEST
        /* Generate second key */
        quitif((priv_eckey = EC_KEY_new()) == NULL, " failed (key alloc 2)\n");
        quitif((group = EC_GROUP_new_by_curve_name(nid)) ==  NULL, " failed (curve alloc 2)\n");
        quitif(EC_KEY_set_group(priv_eckey, group) == 0, " failed (set group 2)\n");
        EC_GROUP_free(group);
        quitif(!EC_KEY_generate_key(priv_eckey), " failed (key gen 2)\n");
        fprintf(stderr, ".");

        /* Check key */
        quitif (!EC_KEY_check_key(eckey), " failed (check key)\n");
        fprintf(stderr, ".");

        /* Sign */
        sig_len = ECDSA_size(eckey);
        fprintf(stderr, "%d", sig_len);
        quitif ((signature = OPENSSL_malloc(sig_len)) == NULL, " malloc error\n");
        memset(signature, 0, sig_len);
        quitif(!ECDSA_sign(0, digest, *len, signature, &sig_len, eckey), " failed (sign)\n");
        fprintf(stderr, ".");
        fprintf(stderr, "%d", sig_len);
        if (nid <= 710 && nid >= 708)
           sig_len = 50;

        /* Verify */
        quitif (ECDSA_verify(0, digest, *len, signature, sig_len, eckey) != 1, " failed (verify)\n");
        fprintf(stderr, ".");

        /* wrong key */
        quitif(ECDSA_verify(0, digest, *len, signature, sig_len,priv_eckey) == 1, " failed (wrong key)\n");
        fprintf(stderr, ".");

        /* wrong digest */
        quitif (ECDSA_verify(0, priv_digest, *len, signature, sig_len,eckey) == 1, " failed (wrong digest)\n");
        fprintf(stderr, ".");

        /* modify a single byte of the signature */
        if (nid <= 710 && nid >= 708)
           offset = signature[10] % 46;
        else
           offset = signature[10] % sig_len;
        dirt   = signature[11];
        signature[offset] ^= dirt ? dirt : 1; 
        quitif (ECDSA_verify(0, digest, *len, signature, sig_len, eckey) == 1, " failed (bit flip %d)\n", offset);
        fprintf(stderr, ".");

        fprintf(stderr, " ok\n");
#endif

        sig_len = ECDSA_size(eckey);
        RAND_pseudo_bytes(blocks, N_ITERS * *len);
        sigs = OPENSSL_malloc(sig_len * N_ITERS);
        do {
            struct timeval tv1, tv2;
            uint64_t time = 0;
            unsigned int sl = 0;
            gettimeofday(&tv1, NULL);
            for (i = 0; i < N_ITERS; i++) {
                quitif(ECDSA_sign(0, blocks + i**len, *len, sigs + i*sig_len, &sl, eckey) !=  1, "sign\n");
            }
            gettimeofday(&tv2, NULL);
            time = 1000000 * (tv2.tv_sec - tv1.tv_sec) + tv2.tv_usec - tv1.tv_usec;
            fprintf(stderr, "\tsign:"/*"\t%ld.%06ld s\t->"*/" %ld.%03ld ms\t", // time / 1000000, time % 1000000,
                    (time / N_ITERS) / 1000, (time / N_ITERS) % 1000);
        } while (0);

        do {
            struct timeval tv1, tv2;
            uint64_t time = 0;
            gettimeofday(&tv1, NULL);
            for (i = 0; i < N_ITERS; i++) {
               quitif(ECDSA_verify(0, blocks + i**len, *len, sigs + i*sig_len, sig_len, eckey) != 1, "verify len(%d)", sig_len);
            }
            gettimeofday(&tv2, NULL);
            time = 1000000 * (tv2.tv_sec - tv1.tv_sec) + tv2.tv_usec - tv1.tv_usec;
            fprintf(stderr, "\tverify:"/*"\t%ld.%06ld s\t->"*/" %ld.%03ld ms\n", // time / 1000000, time % 1000000,
                    (time / N_ITERS) / 1000, (time / N_ITERS) % 1000);
        } while (0);
        OPENSSL_free(sigs);
        sigs = NULL;

#ifdef NORMAL_TEST
        /* cleanup */
        OPENSSL_free(signature);
        signature = NULL;
        EC_KEY_free(eckey);
        eckey = NULL;
        EC_KEY_free(priv_eckey);
        priv_eckey = NULL;
#endif
    }

    if (*++len) {
       goto loop;
    }

        
    return 0;
}
