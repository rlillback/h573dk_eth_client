#ifndef SET_ROOTS_H
#define SET_ROOTS_H

#include <wolfssl/ssl.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Loads the configured root CA certificates into the given wolfSSL_CTX.
 * This function will print debug info and measure timing if enabled.
 *
 * @param ctx Pointer to initialized WOLFSSL_CTX.
 * @param t0 Pointer to store the start tick count (optional).
 * @param t1 Pointer to store the end tick count (optional).
 * @return 0 on success, -1 on failure.
 */
int set_root_cas(WOLFSSL_CTX* ctx, uint32_t* t0, uint32_t* t1);

#ifdef __cplusplus
}
#endif

#endif // SET_ROOTS_H
