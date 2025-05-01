#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include "nx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

UINT https_client_get(const char *host, const char *path, UINT port, CHAR *response_buf, UINT response_buf_size);

#ifdef __cplusplus
}
#endif

#endif // HTTPS_CLIENT_H
