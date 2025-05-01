#ifndef __NETX_TRANSPORT_H__
#define __NETX_TRANSPORT_H__

#include "nx_api.h"
#include "nxd_dns.h"
#include <wolfssl/ssl.h>

#define g_packet_pool      ClientPacketPool
#define g_ip               NetXDuoEthIpInstance
#define g_dns              DnsClient

extern NX_PACKET_POOL g_packet_pool;
extern NX_IP g_ip;
extern NX_DNS g_dns;

typedef struct {
    UCHAR* buffer;
    ULONG offset;
    ULONG len;
} tls_stream_state_t;

void setup_netx_transport(WOLFSSL* ssl, NX_TCP_SOCKET* socket);
void tls_stream_reset(void);

#endif // __NETX_TRANSPORT_H__

