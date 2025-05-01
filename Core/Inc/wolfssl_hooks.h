#ifndef WOLFSSL_HOOKS_H
#define WOLFSSL_HOOKS_H

#include <wolfssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Registers custom memory allocation hooks with wolfSSL.
 */
void setup_allocators(void);

/**
 * Certificate verification callback used by wolfSSL.
 */
int verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store);

#if defined(__PRINT_WOLF_SSL_DEBUG__)
void wolfssl_debug_cb(const int level, const char *const msg);
#endif

#ifdef __cplusplus
}
#endif

#endif // WOLFSSL_HOOKS_H
