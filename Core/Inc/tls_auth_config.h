#ifndef TLS_AUTH_CONFIG_H
#define TLS_AUTH_CONFIG_H

#include <wolfssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Configure the authentication settings (verify mode, client certs if mTLS).
 *
 * @param ctx Pointer to the WOLFSSL_CTX to configure.
 * @param error_flag Pointer to an int to set to 1 if any error occurs.
 * @return 0 if successful, -1 on failure.
 */
int configure_tls_authentication(WOLFSSL_CTX* ctx, int* error_flag);

#ifdef __cplusplus
}
#endif

#endif // TLS_AUTH_CONFIG_H
