#include "nx_api.h"
#include "nx_api.h"       // <-- Needed for DNS, TLS, etc.
#include "nxd_dns.h"       // <-- Specifically for DNS APIs
#include "https_client.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "tx_api.h"
#include "main.h"
#include "stm32_entropy.h"

#include <stdio.h>
#include <string.h>

#define PRINT_IP_ADDRESS(addr) do { \
                                    printf("%lu.%lu.%lu.%lu \r\n", \
                                    (addr >> 24) & 0xff, \
                                    (addr >> 16) & 0xff, \
                                    (addr >> 8) & 0xff, \
                                     addr& 0xff);\
                                  }while(0)

#define g_packet_pool      ClientPacketPool
#define g_ip               NetXDuoEthIpInstance
#define g_dns              DnsClient


extern NX_PACKET_POOL g_packet_pool;
extern NX_IP g_ip;
extern NX_DNS g_dns;

#define HTTPS_TIMEOUT 3000
#define MAX_REQUEST_LEN 512

// Forward declarations
static int net_send(void *ctx, const unsigned char *buf, size_t len);
static int net_recv(void *ctx, unsigned char *buf, size_t len);

// Convert milliseconds to ThreadX ticks
static ULONG ms_to_ticks(UINT ms) {
    return (TX_TIMER_TICKS_PER_SECOND * ms + 999) / 1000;
}

// Set the intermediate and final delays (in milliseconds)
static void threadx_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms) {
    mbedtls_threadx_timer_ctx *tctx = (mbedtls_threadx_timer_ctx *) ctx;

    tctx->intermediate_delay = ms_to_ticks(int_ms);
    tctx->final_delay = ms_to_ticks(fin_ms);
    tctx->start_time = tx_time_get();
    tctx->timer_active = 1;
}

// Get timer state:
//   -1: expired
//    0: ongoing
//    1: intermediate delay passed
static int threadx_get_timer(void *ctx) {
    mbedtls_threadx_timer_ctx *tctx = (mbedtls_threadx_timer_ctx *) ctx;

    if (!tctx->timer_active)
        return -1;

    ULONG elapsed = tx_time_get() - tctx->start_time;

    if (elapsed >= tctx->final_delay) {
        tctx->timer_active = 0;
        return -1; // expired
    }

    if (elapsed >= tctx->intermediate_delay)
        return 1; // intermediate delay passed

    return 0; // ongoing
}

// One-line helper to register callbacks
void mbedtls_ssl_set_threadx_timer_cb(mbedtls_ssl_context *ssl) {
    static mbedtls_threadx_timer_ctx timer_ctx;
    mbedtls_ssl_set_timer_cb(ssl, &timer_ctx, threadx_set_timer, threadx_get_timer);
}

// TLS wrappers for NetX socket
static int net_send(void *ctx, const unsigned char *buf, size_t len) {
	printf("Entered net_send function...\r\n");
    NX_TCP_SOCKET *socket = (NX_TCP_SOCKET *)ctx;
    NX_PACKET *packet;
    if (nx_packet_allocate(&g_packet_pool, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER) != NX_SUCCESS)
        return MBEDTLS_ERR_NET_SEND_FAILED;

    if (nx_packet_data_append(packet, (VOID *)buf, len, &g_packet_pool, NX_WAIT_FOREVER) != NX_SUCCESS)
        return MBEDTLS_ERR_NET_SEND_FAILED;

    if (nx_tcp_socket_send(socket, packet, NX_WAIT_FOREVER) != NX_SUCCESS)
        return MBEDTLS_ERR_NET_SEND_FAILED;

    return (int)len;
}

static int net_recv(void *ctx, unsigned char *buf, size_t len) {
	printf("Entered net_recv function...\r\n");
    NX_TCP_SOCKET *socket = (NX_TCP_SOCKET *)ctx;
    NX_PACKET *packet;
    UINT status = nx_tcp_socket_receive(socket, &packet, HTTPS_TIMEOUT);

    if (status != NX_SUCCESS)
        return MBEDTLS_ERR_SSL_TIMEOUT;

    ULONG bytes_copied;
    status = nx_packet_data_extract_offset(packet, 0, buf, len, &bytes_copied);
    nx_packet_release(packet);

    if (status != NX_SUCCESS)
        return MBEDTLS_ERR_NET_RECV_FAILED;

    return (int)bytes_copied;
}

UINT https_client_get(const char *host, const char *path, UINT port, CHAR *response_buf, UINT response_buf_size) {
	printf("Entered https_client_get function...\r\n");
    NX_TCP_SOCKET socket;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt ca_cert;
    const char *pers = "nx_https_client";

    UINT status;
    CHAR request[MAX_REQUEST_LEN];
    int retval;

    // Create NetX TCP socket
    printf("Creating socket via nx_tcp_socket_create...\r\n");
    status = nx_tcp_socket_create(&g_ip, &socket, "https_client_socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                  NX_NULL, NX_NULL);
    if (status != NX_SUCCESS) {
    	printf("Socket creation failed with error code 0x%02X\r\n",status);
    	Error_Handler();
    }
    printf("Socket creation successful...\r\nAttempting to bind socket to port...\r\n");

    status = nx_tcp_client_socket_bind(&socket, NX_ANY_PORT, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
    	printf("Socket bind failed with error code 0x%02X\r\n", status);
    	Error_Handler();
    }
    printf("Socket bind successful...\r\n");

    ULONG ip_address;
    printf("Looking up hostname %s IP address using DNS...\r\n", host);
    status = nx_dns_host_by_name_get(&g_dns, (UCHAR *)host, &ip_address, NX_WAIT_FOREVER);
    if (status != 0) {
    	printf("nx_dns_host_by_name_get failed with code 0x%02X\r\n", status);
    	Error_Handler();
    }
    printf("Hostname %s returned and IP Address of\r\n", host);
    PRINT_IP_ADDRESS(ip_address);

    printf("Connecting to socket using port %u...\r\n", port);
    status = nx_tcp_client_socket_connect(&socket, ip_address, port, NX_WAIT_FOREVER);
    if (status != 0) {
      	printf("nx_tcp_client_socket_connect failed with code 0x%02X\r\n", status);
       	Error_Handler();
    }

    // TLS setup
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    // ✅ Register your entropy source here
	retval = mbedtls_entropy_add_source(&entropy,
									 mbedtls_hardware_poll,
									 NULL,
									 32, // Minimum bytes of entropy (usually 32)
									 MBEDTLS_ENTROPY_SOURCE_STRONG);
	if (retval != 0) {
		printf("mbedtls_entropy_add_source failed: -0x%X\r\n", -retval);
		goto cleanup;
	}
	printf("mbedtls_entropy_add_source successful...\r\n");
    mbedtls_x509_crt_init(&ca_cert);

    printf("Seeding DRBG via mbedtls_ctr_drbg_seed...\r\n");
    retval = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                mbedtls_entropy_func,
                                &entropy,
                                (const unsigned char *)pers,
                                strlen(pers));
    if (retval != 0) {
        printf("DRBG seed failed: -0x%X\r\n", -retval);
        Error_Handler();
    }
    printf("DRBG seed successful....\r\n");

    retval = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (retval != 0) {
        printf("mbedtls_ssl_config_defaults failed: -0x%X\r\n", -retval);
        Error_Handler();
    }
    printf("mbedtls_ssl_config_defaults successful...\r\n");

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    retval = mbedtls_ssl_setup(&ssl, &conf);
    if (retval != 0) {
        printf("ssl_setup failed: -0x%X\r\n", -retval);
        Error_Handler();
    }
    printf("mbedtls_ssl_config_defaults successful...\r\n");

    printf("Registering callback via mbedtls_ssl_set_threadx_timer_cb...\r\n");
    mbedtls_ssl_set_threadx_timer_cb(&ssl);

    mbedtls_ssl_set_bio(&ssl, &socket, net_send, net_recv, NULL);
    printf("mbedtls_ssl_set_bio finished...\r\n");

    // ✅ Check that socket is connected
    if (socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) {
        printf("Socket is not connected (state = 0x%x)\r\n", socket.nx_tcp_socket_state);
        Error_Handler();
    }
    printf("Socked is connected...\r\n");

    // TLS handshake
    retval = mbedtls_ssl_handshake(&ssl);
    if (retval != 0) {
    	printf("Failed mbedtls_ssl_handshake with code  -0x%X\r\n", -retval);
    	mbedtls_ssl_free(&ssl);
    	mbedtls_ssl_config_free(&conf);
    	mbedtls_ctr_drbg_free(&ctr_drbg);
    	mbedtls_entropy_free(&entropy);
    	mbedtls_x509_crt_free(&ca_cert);

    	nx_tcp_socket_disconnect(&socket, NX_WAIT_FOREVER);
    	nx_tcp_client_socket_unbind(&socket);
    	nx_tcp_socket_delete(&socket);
    	Error_Handler();
    }
    printf("mbedtls_ssl_handshake successful...\r\n");

    // HTTP GET request
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept:application/json\r\n\r\n",
             path, host);

    retval = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request));
    if (retval <= 0) {
        printf("mbedtls_ssl_write failed: -0x%X\r\n", -retval);
        Error_Handler();
    }
    printf("mbedtls_ssl_write successful...\r\n");

    printf("Got a good mbedtls_ssl_write using this request:\r\n%s", request);

    int total = 0, ret;
    while (1) {
    	ret = mbedtls_ssl_read(&ssl,
    			              (unsigned char *)response_buf + total,
							  response_buf_size - total - 1);
    	if (ret <= 0) break;
        total += ret;
    }
    response_buf[total] = '\0';
    printf("response_buf =\r\n%s", response_buf);

cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&ca_cert);

    nx_tcp_socket_disconnect(&socket, NX_WAIT_FOREVER);
    nx_tcp_client_socket_unbind(&socket);
    nx_tcp_socket_delete(&socket);

    return NX_SUCCESS;
} /* https_client_get */
