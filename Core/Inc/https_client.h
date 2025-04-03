
#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include "nx_api.h"

int https_client_get(NX_TCP_SOCKET *socket, const char *host, const char *path);

#endif // HTTPS_CLIENT_H
