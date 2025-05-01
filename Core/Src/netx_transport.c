#include "main.h"
#include "netx_transport.h"
#include "app_netxduo.h"
#include "nx_api.h"

#include <stdio.h>
#include <string.h>

extern NX_PACKET_POOL g_packet_pool;

static UCHAR tls_stream_buffer[MAX_TLS_RECORD_SIZE];
static tls_stream_state_t tls_stream;

static void get_nx_packet(NX_TCP_SOCKET *socket, NX_PACKET **packet_ptr, UINT *status);
static int net_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static int net_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);

static void get_nx_packet(NX_TCP_SOCKET *socket, NX_PACKET **packet_ptr, UINT *status)
{
	int retries = 0;
	do {
		printf("calling nx_tcp_socket_receive(timeout=3000)...\r\n");
		*status = nx_tcp_socket_receive(socket, packet_ptr, 3000);
		printf("socket state = 0x%02X, status = 0x%X, packet ptr = 0x%p\r\n",
			   socket->nx_tcp_socket_state, *status, *packet_ptr);
		if (*packet_ptr) {
			printf("this packet's length = %lu\r\n", (*packet_ptr)->nx_packet_length);
		}
		if (*status == NX_SUCCESS || retries >= 5) {
			printf("nx_tcp_socket_receive returned code %u\r\n", *status);
			break;
		}
		printf("net_recv: retrying receive (attempt %d)...\r\n", retries + 1);
		tx_thread_sleep(5);
	} while (++retries < 5);
}

static int net_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
	NX_TCP_SOCKET *socket = (NX_TCP_SOCKET *)ctx;
	tls_stream_state_t *stream = &tls_stream;

    UINT status;
    NX_PACKET *packet = NULL;
    ULONG copied = 0;
    ULONG left_to_give = 0;

#if defined(__DUMP_CLIENT_PACKET_POOL__)
    print_pool_state(&g_packet_pool, "[DEBUG] Client packet pool @ net_send");
#endif

    if (stream->offset > stream->len) {
    	printf("Error we have a stream offset larger than the length of the stream...\r\n");
    	return WOLFSSL_CBIO_ERR_GENERAL;
    } else {
    	left_to_give = (stream->len - stream->offset);
    }

#if defined(__PRINT_NET_RECV_DATA__)
    printf("net_recv function entered...\r\n");
	printf("  ssl ptr = 0x%x\r\n", (UINT)ssl);
	printf("  buf ptr = 0x%x\r\n", (UINT)&buf);
	printf("  sz = %d\r\n", sz);
	printf("  ctx ptr = 0x%x\r\n", (UINT)ctx);
	printf("  stream->offset=%lu\r\n stream->len=%lu\r\n", stream->offset, stream->len);
	printf("  bytes_still_left in buffer=%lu\r\n", left_to_give);
#endif

    if (left_to_give >= sz) {
#if defined(__PRINT_NET_RECV_DATA__)
    	printf("We don't need to retrieve any more data, so returning the next requested data\r\n");
#endif
		memcpy(buf, &stream->buffer[stream->offset], sz);

#if defined(__DUMP_WOLFSSL_PACKETS__)
		printf("➡️  net_recv returning %d bytes to wolfSSL without reading next packet:\r\n", sz);
		for (ULONG i = 0; i < sz; i += 16) {
			printf("  %04lX: ", i);
			for (ULONG j = 0; j < 16 && (i + j) < sz; ++j) {
				printf("%02X ", buf[i + j]);
			}
			printf("\r\n");
		}
#endif

		stream->offset += sz;
#if defined(__RESET_STREAM_MID_EXCHANGE__)
		if (stream->offset >= stream->len) {
			printf("We need to reset our buffer, as we already served everything...\r\n");
		    tls_stream_reset();
		}
#endif
		return sz;
    }

	get_nx_packet(socket, &packet, &status);
	copied = 0;
	status = nx_packet_data_extract_offset(packet,
										   0,
										   &stream->buffer[stream->len],
										   MAX_TLS_RECORD_SIZE - stream->len,
										   &copied);

	if (status != NX_SUCCESS) {
		printf("net_recv: receive error 0x%X\r\n", status);
		return WOLFSSL_CBIO_ERR_WANT_READ;
	}

	if (packet &&
		packet->nx_packet_length == 0 &&
		socket->nx_tcp_socket_state == NX_TCP_CLOSE_WAIT) {
		printf("net_recv: socket in CLOSE_WAIT — returning EOF to wolfSSL\r\n");
		nx_packet_release(packet);
		return 0;
	}

	if (copied == 0) {
		printf("net_recv: data extract error or zero copy\r\n");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	printf("We copied %lu bytes from the wire\r\n", copied);
#if defined(__MSS_PACKET_DUMP__)
	printf("Dumping this MSS packet...\r\n");
	for (ULONG i = 0; i < copied; i += 16) {
		printf("  %04lX: ", i);
		for (ULONG j = 0; j < 16 && (i + j) < copied; ++j) {
			printf("%02X ", stream->buffer[stream->offset + i + j]);
		}
		printf("\r\n");
	}
#endif
	stream->len += copied;
	nx_packet_release(packet);
	packet = NULL;
    return 0;
}

static int net_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
	printf("net_send function entered...\r\n");
    NX_TCP_SOCKET *socket = (NX_TCP_SOCKET *)ctx;
    NX_PACKET *packet;
    if (nx_packet_allocate(&g_packet_pool, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER) != NX_SUCCESS)
        return WOLFSSL_CBIO_ERR_GENERAL;

    if (nx_packet_data_append(packet, buf, sz, &g_packet_pool, NX_WAIT_FOREVER) != NX_SUCCESS)
        return WOLFSSL_CBIO_ERR_GENERAL;

    if (nx_tcp_socket_send(socket, packet, NX_WAIT_FOREVER) != NX_SUCCESS)
        return WOLFSSL_CBIO_ERR_GENERAL;

#if defined(__DUMP_CLIENT_PACKET_POOL__)
    print_pool_state(&g_packet_pool, "[DEBUG] Client packet pool @ net_send");
#endif
    return sz;
}

void setup_netx_transport(WOLFSSL* ssl, NX_TCP_SOCKET* socket) {
    wolfSSL_SSLSetIORecv(ssl, net_recv);
    wolfSSL_SSLSetIOSend(ssl, net_send);
    wolfSSL_SetIOReadCtx(ssl, socket);
    wolfSSL_SetIOWriteCtx(ssl, socket);
}

void tls_stream_reset(void) {
	tls_stream.buffer = tls_stream_buffer;
    tls_stream.len = 0;
    tls_stream.offset = 0;
}
