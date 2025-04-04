#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include "nx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int https_client_get(NX_TCP_SOCKET *socket, const char *host, const char *path);

#ifdef __cplusplus
}
#endif

#endif // HTTPS_CLIENT_H
