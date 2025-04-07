#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include "nx_api.h"
#include "mbedtls/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

// Timer context structure
typedef struct {
    ULONG start_time;
    ULONG intermediate_delay;
    ULONG final_delay;
    int timer_active;
} mbedtls_threadx_timer_ctx;

// Callback registration
void mbedtls_ssl_set_threadx_timer_cb(mbedtls_ssl_context *ssl);

UINT https_client_get(const char *host, const char *path, UINT port, CHAR *response_buf, UINT response_buf_size);

#ifdef __cplusplus
}
#endif

#endif // HTTPS_CLIENT_H
