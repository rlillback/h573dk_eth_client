#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include "nx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_HEADER_SIZE 5
#define MAX_TLS_RECORD_SIZE (16 * 1024)

typedef struct {
    UCHAR *buffer;  					// Assembled TLS record buffer
    ULONG len;                          // Total bytes assembled so far
    ULONG offset;                       // How much data has been handed off to wolfSSL
} tls_stream_state_t;

UINT https_client_get(const char *host, const char *path, UINT port, CHAR *response_buf, UINT response_buf_size);

#ifdef __cplusplus
}
#endif

#endif // HTTPS_CLIENT_H
