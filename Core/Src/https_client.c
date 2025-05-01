#include "main.h"
#include "https_client.h"
#include "netx_transport.h"
#include "wolfssl_hooks.h"
#include "wolfssl_utilities.h"
#include "set_roots.h"
#include "tls_auth_config.h"
#include <stdio.h>
#include <string.h>
#include <tx_api.h>

#include "tx_api.h"
#include "nx_tcp.h"
#include "nx_api.h"
#include "nxd_dns.h"
#include "app_netxduo.h"

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/version.h>

#define g_packet_pool      ClientPacketPool
#define g_ip               NetXDuoEthIpInstance
#define g_dns              DnsClient

extern NX_PACKET_POOL g_packet_pool;
extern NX_IP g_ip;
extern NX_DNS g_dns;

int connect_with_retries(WOLFSSL* ssl);
int read_with_retries(WOLFSSL* ssl, char* buffer, int len);
int write_with_retries(WOLFSSL* ssl, const char* buffer, int len);

UINT https_client_get(const char *host, const char *path, UINT port, CHAR *response_buf, UINT response_buf_size) {
    NX_TCP_SOCKET socket;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    int ret;
    CHAR request[MAX_REQUEST_LEN];
    int error_occurred = 0;
    ULONG t0, t1;

    const char* version = wolfSSL_lib_version();
    printf("wolfSSL version: %s\r\n", version);

	printf("Listing available wolfssl ciphers...\r\n");
	print_ciphers(); // Optional: Print enabled ciphers

    printf("Setting allocator hooks to watch memory...\r\n");
    setup_allocators();

    t0 = tx_time_get();
    printf("Calling wolfSSL_Init...\r\n");
    wolfSSL_Init();
    t1 = tx_time_get();
    printf("wolfSSL_Init done in %lu ticks\r\n", t1 - t0);

#if defined(__PRINT_WOLF_SSL_DEBUG__)
    printf("Calling wolfSSL_Debugging_ON...\r\n");
    wolfSSL_Debugging_ON();
    printf("Setting wolfSSL_SetLoggingCb...\r\n");
    wolfSSL_SetLoggingCb(wolfssl_debug_cb);
#endif

    t0 = tx_time_get();
    printf("Calling wolfSSL_CTX_new...\r\n");
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        printf("wolfSSL_CTX_new error\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("wolfSSL_CTX_new successful in %lu ticks\r\n", t1 - t0);

    if (set_root_cas(ctx, &t0, &t1) != 0) {
    	printf("[ERROR] Error setting root CA certificates\r\n");
        error_occurred = 1;
        goto cleanup;
    }

    printf("Setting verify mode with wolfSSL_CTX_set_verify...\r\n");
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);


    if (configure_tls_authentication(ctx, &error_occurred) != 0) {
        goto cleanup;
    }

	t0 = tx_time_get();
	printf("Calling wolfSSL_new...\r\n");
	if ((ssl = wolfSSL_new(ctx)) == NULL) {
		printf("wolfSSL_new error\r\n");
		error_occurred = 1;
		goto cleanup;
	}
	t1 = tx_time_get();
	printf("wolfSSL_new successful in %lu ticks\r\n", t1 - t0);

    t0 = tx_time_get();
    printf("Creating TCP socket...\r\n");
    if (nx_tcp_socket_create(&g_ip, &socket, "https_client_socket",
                             NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                             NX_NULL, NX_NULL) != NX_SUCCESS) {
        printf("Socket create failed\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("TCP socket created in %lu ticks\r\n", t1 - t0);

    t0 = tx_time_get();
    printf("Binding socket...\r\n");
    if (nx_tcp_client_socket_bind(&socket, NX_ANY_PORT, NX_WAIT_FOREVER) != NX_SUCCESS) {
        printf("Socket bind failed\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("Socket bound in %lu ticks\r\n", t1 - t0);

    ULONG ip_address;
    t0 = tx_time_get();
    printf("Performing DNS lookup...\r\n");
    if (nx_dns_host_by_name_get(&g_dns, (UCHAR *)host, &ip_address, NX_WAIT_FOREVER) != NX_SUCCESS) {
        printf("DNS lookup failed\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("DNS lookup successful in %lu ticks\r\n", t1 - t0);

    PRINT_IP_ADDRESS(ip_address);

    t0 = tx_time_get();
    printf("Connecting socket...\r\n");
    if (nx_tcp_client_socket_connect(&socket, ip_address, port, NX_WAIT_FOREVER) != NX_SUCCESS) {
        printf("Socket connect failed\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("Socket connected in %lu ticks\r\n", t1 - t0);

    printf("Resetting TLS stream state...\r\n");
    tls_stream_reset();

    printf("Setting wolfSSL IO callbacks...\r\n");
    setup_netx_transport(ssl, &socket);
    printf("wolfSSL IO callbacks set successfully...\r\n");

    printf("Setting SNI using wolfSSL_UseSNI...\r\n");
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, strlen(host));
    if (ret != WOLFSSL_SUCCESS) {
		printf("wolfSSL_UseSNI failed: %d\r\n", ret);
		Error_Handler();
	}
	printf("wolfSSL_UseSNI success...\r\n");

    printf("Setting ALPN using wolfSSL_UseALPN...\r\n");
    const unsigned char alpn[] = {
        0x08, 'h','t','t','p','/','1','.','1'
    };
    ret = wolfSSL_UseALPN(ssl, (char*)alpn, sizeof(alpn), WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
    if (ret != WOLFSSL_SUCCESS) {
        printf("❌ wolfSSL_UseALPN failed: %d\r\n", ret);
        Error_Handler();
    }
    printf("wolfSSL_UseALPN success...\r\n");

    ULONG socket_state = 0;
    UINT status = nx_tcp_socket_info_get(
        &socket,
        NULL, NULL,  // packets sent, bytes sent
        NULL, NULL,  // packets received, bytes received
        NULL, NULL,  // retransmit packets, packets queued
        NULL,        // checksum errors
        &socket_state,
        NULL, NULL, NULL  // transmit queue, tx win, rx win
    );

    if (status == NX_SUCCESS) {
        printf("🔍 Socket state: 0x%02lX (%s)\r\n", socket_state,
               socket_state == NX_TCP_ESTABLISHED ? "ESTABLISHED" : "NOT ESTABLISHED");
    } else {
        printf("Failed to get socket info, status: 0x%X\r\n", status);
    }

    t0 = tx_time_get();
    printf("Performing TLS handshake...\r\n");

    if ((ret = connect_with_retries(ssl)) != SSL_SUCCESS) {
        char err[80];
        wolfSSL_ERR_error_string(wolfSSL_get_error(ssl, ret), err);
        printf("TLS handshake failed: %s\r\n", err);
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("TLS handshake successful in %lu ticks\r\n", t1 - t0);

    const char* cipher = wolfSSL_get_cipher_name(ssl);
    if (cipher)
        printf("Negotiated cipher: %s\r\n", cipher);

    printf("Preparing HTTP GET request...\r\n");
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept:application/json\r\n\r\n",
             path, host);
    printf("HTTP GET request prepared...\r\n");

    t0 = tx_time_get();
    printf("Sending HTTPS request...of:\r\n\r\n%s",request);
    if ((ret = write_with_retries(ssl, request, strlen(request))) <= 0) {
        printf("TLS write failed\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("HTTPS request sent in %lu ticks\r\n", t1 - t0);

    int total = 0;
    printf("Reading HTTPS response...\r\n");
    t0 = tx_time_get();
    while (total < (int)(response_buf_size - 1)) {
        ret = read_with_retries(ssl, response_buf + total, response_buf_size - 1 - total);
        if (ret <= 0) break;
        total += ret;
    }
    t1 = tx_time_get();
    printf("HTTPS response read in %lu ticks\r\n", t1 - t0);

    response_buf[total] = '\0';
#if defined(__PRINT_HTTPS_RESPONSES__)
    printf("HTTPS response received:\r\n\r\n%s\r\n\r\n", response_buf);
#endif

cleanup:
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    nx_tcp_socket_disconnect(&socket, NX_WAIT_FOREVER);
    nx_tcp_client_socket_unbind(&socket);
    nx_tcp_socket_delete(&socket);

    if (error_occurred) {
        Error_Handler();
    }

    return error_occurred ? NX_NOT_SUCCESSFUL : NX_SUCCESS;
}

int connect_with_retries(WOLFSSL* ssl)
{
	printf("Entered connect_with_retries...\r\n");
    int err, retries = 0;
    int ret = WOLFSSL_SUCCESS;
    do {
    	print_pool_state(&ClientPacketPool, "Before wolfSSL_connect");
        ret = wolfSSL_connect(ssl);
        print_pool_state(&ClientPacketPool, "After wolfSSL_connect");
        if (ret == WOLFSSL_SUCCESS) {
        	printf("connect_with_retries finished good...\r\n");
        	return WOLFSSL_SUCCESS;
        }

        err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_CBIO_ERR_WANT_READ || err == WOLFSSL_CBIO_ERR_WANT_WRITE) {
        	printf("connect_with_retries sleeping for %d ticks\r\n", TLS_SLEEP_TICKS);
            tx_thread_sleep(TLS_SLEEP_TICKS);
            retries++;
            continue;
        }

        printf("wolfSSL_connect failed: %s\r\n", wolfSSL_ERR_reason_error_string(err));
        return ret;
    } while (retries < TLS_MAX_RETRIES);

    printf("wolfSSL_connect timed out after %d retries\r\n", retries);
    return -1;
}

int read_with_retries(WOLFSSL* ssl, char* buffer, int len)
{
	printf("Entered read_with_retries...\r\n");
	int err, retries = 0;
	int ret = WOLFSSL_SUCCESS;
    do {
    	printf("Executing wolfSSL_read...\r\n");
        ret = wolfSSL_read(ssl, buffer, len);
        printf("wolfSSL_read returned code %d\r\n", ret);
        if (ret > 0) {
        	printf("read_with_retries finished good...\r\n");
        	return ret;
        }

        err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_CBIO_ERR_WANT_READ || err == WOLFSSL_CBIO_ERR_WANT_WRITE) {
        	printf("read_with_retries sleeping for %d ticks\r\n", TLS_SLEEP_TICKS);
            tx_thread_sleep(TLS_SLEEP_TICKS);
            retries++;
            continue;
        }

        printf("wolfSSL_read failed: %s\r\n", wolfSSL_ERR_reason_error_string(err));
        return ret;
    } while (retries < TLS_MAX_RETRIES);

    printf("wolfSSL_read timed out after %d retries\r\n", retries);
    return -1;
}

int write_with_retries(WOLFSSL* ssl, const char* buffer, int len)
{
	printf("Entered write_with_retries...\r\n");
	int err, retries = 0;
	int ret = WOLFSSL_SUCCESS;
    do {
        ret = wolfSSL_write(ssl, buffer, len);
        if (ret > 0) {
        	printf("write_with_retries finished good...\r\n");
        	return ret;
        }

        err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_CBIO_ERR_WANT_READ || err == WOLFSSL_CBIO_ERR_WANT_WRITE) {
        	printf("write_with_retries sleeping for %d ticks\r\n", TLS_SLEEP_TICKS);
            tx_thread_sleep(TLS_SLEEP_TICKS);
            retries++;
            continue;
        }

        printf("wolfSSL_write failed: %s\r\n", wolfSSL_ERR_reason_error_string(err));
        return ret;
    } while (retries < TLS_MAX_RETRIES);

    printf("wolfSSL_write timed out after %d retries\r\n", retries);
    return -1;
}


