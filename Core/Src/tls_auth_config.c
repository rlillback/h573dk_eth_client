#include "main.h"
#include "tls_auth_config.h"
#if defined(__USE_MTLS__)
	#include "client_pems.h"
#endif
#include <string.h>
#include <stdio.h>

extern int verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store);

int configure_tls_authentication(WOLFSSL_CTX* ctx, int* error_flag)
{
#if defined(__USE_ONE_WAY_TLS__)
    printf("Setting wolfSSL verify callback function...\r\n");
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);

#elif defined(__USE_MTLS__)
    printf("Binding client cert and key to SSL session...\r\n");

    if (wolfSSL_CTX_use_certificate_chain_buffer(ctx,
            (const unsigned char*)client_cert_chain_pem,
            strlen(client_cert_chain_pem)) != SSL_SUCCESS) {
        printf("wolfSSL_use_certificate_chain_buffer error!\r\n");
        if (error_flag) *error_flag = 1;
        return -1;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,
            (const unsigned char*)client_key_pem,
            strlen(client_key_pem),
            WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("wolfSSL_use_PrivateKey_buffer error!\r\n");
        if (error_flag) *error_flag = 1;
        return -1;
    }

    printf("Setting wolfSSL verify callback function...\r\n");
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_cb);

#elif !defined(__HTTP__ONLY_)
    // Do Nothing
#else
    #error "Must have either one way or mTLS defined"
#endif

    return 0;
}
