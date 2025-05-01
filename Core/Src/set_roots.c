#include "set_roots.h"
#include "root_pems.h"
#include "main.h"

#include <stdio.h>
#include <string.h>
#include <tx_api.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/ssl.h>

extern void print_cert_subject_from_pem(const char* pem, const char* label);

int set_root_cas(WOLFSSL_CTX* ctx, uint32_t* t0, uint32_t* t1) {
#if !defined(__LOAD_AMAZON_CA__) && !defined(__LOAD_DIGICERT_CA__) && !defined(__LOAD_ENTRUST_CA__)
    #error "At least one root CA must be loaded"
#endif

#if defined(__LOAD_AMAZON_CA__)
    print_cert_subject_from_pem(amazon_root_ca1_pem, "Loading Root CA");
    if (t0) *t0 = tx_time_get();
    printf("Calling wolfSSL_CTX_load_verify_buffer...\r\n");
    if (wolfSSL_CTX_load_verify_buffer(ctx,
            (const unsigned char *)amazon_root_ca1_pem,
            strlen(amazon_root_ca1_pem),
            WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("wolfSSL_CTX_load_verify_buffer error\r\n");
        return -1;
    }
    if (t1) *t1 = tx_time_get();
    printf("wolfSSL_CTX_load_verify_buffer successful in %lu ticks\r\n", (t1 && t0) ? (*t1 - *t0) : 0);
#endif

#if defined(__LOAD_DIGICERT_CA__)
    print_cert_subject_from_pem(digicert_global_root_c3_pem, "Loading Root CA");
    if (t0) *t0 = tx_time_get();
    printf("Calling wolfSSL_CTX_load_verify_buffer...\r\n");
    if (wolfSSL_CTX_load_verify_buffer(ctx,
            (const unsigned char *)digicert_global_root_c3_pem,
            strlen(digicert_global_root_c3_pem),
            WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("wolfSSL_CTX_load_verify_buffer error\r\n");
        return -1;
    }
    if (t1) *t1 = tx_time_get();
    printf("wolfSSL_CTX_load_verify_buffer successful in %lu ticks\r\n", (t1 && t0) ? (*t1 - *t0) : 0);
#endif

#if defined(__LOAD_ENTRUST_CA__)
    print_cert_subject_from_pem(lets_encrypt_root_r11, "Loading Root CA");
    if (t0) *t0 = tx_time_get();
    printf("Calling wolfSSL_CTX_load_verify_buffer...\r\n");
    if (wolfSSL_CTX_load_verify_buffer(ctx,
            (const unsigned char *)lets_encrypt_root_r11,
            strlen(lets_encrypt_root_r11),
            WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("wolfSSL_CTX_load_verify_buffer error\r\n");
        return -1;
    }
    if (t1) *t1 = tx_time_get();
    printf("wolfSSL_CTX_load_verify_buffer successful in %lu ticks\r\n", (t1 && t0) ? (*t1 - *t0) : 0);
#endif

    return 0;
}
