#include "nx_api.h"
#include "nxd_dns.h"
#include "https_client.h"
#include "main.h"
#include "root_pems.h"
#include <stdio.h>
#include <string.h>
#include <tx_api.h>

#include "tx_api.h"
#include "nx_tcp.h"
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

#if !defined(WOLFSSL_DEBUG_LEVEL)
	#define WOLFSSL_DEBUG_LEVEL 6
#endif

#define g_packet_pool      ClientPacketPool
#define g_ip               NetXDuoEthIpInstance
#define g_dns              DnsClient

extern NX_PACKET_POOL g_packet_pool;
extern NX_IP g_ip;
extern NX_DNS g_dns;

#define HTTPS_TIMEOUT 3000
#define MAX_REQUEST_LEN 512

#define TLS_MAX_RETRIES 200
#define TLS_SLEEP_TICKS 5

// Optional debug toggles
#undef  __MSS_PACKET_DUMP__
#undef  __DUMP_WOLFSSL_PACKETS__
#undef  __PRINT_ALLOCATIONS__
#undef  __PRINT_WOLF_SSL_DEBUG__
#undef  __PRINT_HTTPS_RESPONSES__
#undef  __PRINT_NET_RECV_DATA__
#undef  __DUMP_CLIENT_PACKET_POOL__

// CA Certificate roots to load
#undef  __LOAD_AMAZON_CA__
#undef  __LOAD_DIGICERT_CA__
#define __LOAD_ENTRUST_CA__

int connect_with_retries(WOLFSSL* ssl);
int read_with_retries(WOLFSSL* ssl, char* buffer, int len);
int write_with_retries(WOLFSSL* ssl, const char* buffer, int len);
void print_cert_subject_from_pem(const char* pem, const char* label);
static void print_ciphers(void);
static void tls_stream_reset(void);

static UCHAR tls_stream_buffer[MAX_TLS_RECORD_SIZE];

static tls_stream_state_t tls_stream;

static void* malloc_wrapper(size_t sz, void* heap, int type)
{
    void* p = malloc(sz);
    if (!p) {
		printf("XMALLOC failed! type=%d, size=%lu\r\n", type, (unsigned long)sz);
		Error_Handler();
	}
#if defined(__PRINT_ALLOCATIONS__)
    else {
    	printf("XMALLOC(type=%d, size=%lu) = %p\r\n", type, (unsigned long)sz, p);
    }
#endif
    return p;
}

static void free_wrapper(void* p, void* heap, int type)
{
#if defined(__PRINT_ALLOCATIONS__)
    printf("XFREE(type=%d, ptr=%p)\r\n", type, p);
#endif
    free(p);
}

static void* realloc_wrapper(void* p, size_t n, void* heap, int type)
{
    void* np = realloc(p, n);
#if defined(__PRINT_ALLOCATIONS__)
    printf("XREALLOC(type=%d, new_size=%lu) = %p\n", type, (unsigned long)n, np);
#endif
    return np;
}

void setup_allocators() {
    wolfSSL_SetAllocators((wolfSSL_Malloc_cb)malloc_wrapper,
    		              (wolfSSL_Free_cb)free_wrapper,
						  (wolfSSL_Realloc_cb)realloc_wrapper);
}

int verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store) {
    return preverify;
} /* verify_cb */

#if defined(__PRINT_WOLF_SSL_DEBUG__)
void wolfssl_debug_cb(const int level, const char *const msg) {
	if (level <= WOLFSSL_DEBUG_LEVEL) {
		printf("[wolfSSL][%d] %s\r\n", level, msg);
	}
}
#endif

static int net_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
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

void get_nx_packet(NX_TCP_SOCKET *socket, NX_PACKET **packet_ptr, UINT *status)
{
	int retries = 0;
	do {
		printf("calling nx_tcp_socket_receive(timeout=%u)...\r\n", HTTPS_TIMEOUT);
		*status = nx_tcp_socket_receive(socket, packet_ptr, HTTPS_TIMEOUT);
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

int net_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
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
	printf(" ctx ptr = 0x%x\r\n", (UINT)ctx);
	printf(" stream->offset=%lu\r\n stream->len=%lu\r\n", stream->offset, stream->len);
	printf(" bytes_still_left in buffer=%lu\r\n", left_to_give);
#endif

    // Do we have enough data to fufill wolfSSL's request?
    // If so, give it to wolfSSL
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

		stream->offset += sz; // Update the offset into our buffer
#if defined(__RESET_STREAM_MID_EXCHANGE__)
		if (stream->offset >= stream->len) {
			printf("We need to reset our buffer, as we already served everything...\r\n");
		    tls_stream_reset();
		}
#endif
		return sz;
    }

    // If we get here, we need to read more data off of the wire
	get_nx_packet(socket, &packet, &status);
	// Extract packet data into the TLS buffer
	copied = 0;
	status = nx_packet_data_extract_offset(packet, // Pointer to the packet
										   0,      // Offset in the packet from which we should copy
										   &stream->buffer[stream->len], // The start of the buffer
										   MAX_TLS_RECORD_SIZE - stream->len, // The length left in the buffer
										   &copied); // Number of bytes that were copied into the buffer

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
	stream->len += copied; // Expand the end of our buffer
	nx_packet_release(packet);
	packet = NULL;
    return 0; // Tell wolfSSL to try the read again to see if we have enough data to serve
}


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

    printf("Setting wolfSSL verify callback function...\r\n");
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);

    t0 = tx_time_get();
    printf("Calling wolfSSL_CTX_new...\r\n");
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        printf("wolfSSL_CTX_new error\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("wolfSSL_CTX_new successful in %lu ticks\r\n", t1 - t0);

#if !defined(__LOAD_AMAZON_CA__) && !defined(__LOAD_DIGICERT_CA__) && !defined(__LOAD_ENTRUST_CA__)
	#error "At least once root CA must be loaded"
#endif

#if defined(__LOAD_AMAZON_CA__)
    print_cert_subject_from_pem(amazon_root_ca1_pem, "Loading Root CA");
    t0 = tx_time_get();
    printf("Calling wolfSSL_CTX_load_verify_buffer...\r\n");
    if (wolfSSL_CTX_load_verify_buffer(ctx, (const unsigned char *)amazon_root_ca1_pem,
                                       strlen(amazon_root_ca1_pem), WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("wolfSSL_CTX_load_verify_buffer error\r\n");
        error_occurred = 1;
        goto cleanup;
    }
    t1 = tx_time_get();
    printf("wolfSSL_CTX_load_verify_buffer successful in %lu ticks\r\n", t1 - t0);
#endif

#if defined(__LOAD_DIGICERT_CA__)
    print_cert_subject_from_pem(digicert_global_root_c3_pem, "Loading Root CA");
    t0 = tx_time_get();
	printf("Calling wolfSSL_CTX_load_verify_buffer...\r\n");
	if (wolfSSL_CTX_load_verify_buffer(ctx, (const unsigned char *)digicert_global_root_c3_pem,
									   strlen(digicert_global_root_c3_pem), WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
		printf("wolfSSL_CTX_load_verify_buffer error\r\n");
		error_occurred = 1;
		goto cleanup;
	}
	t1 = tx_time_get();
	printf("wolfSSL_CTX_load_verify_buffer successful in %lu ticks\r\n", t1 - t0);
#endif

#if defined(__LOAD_ENTRUST_CA__)
	print_cert_subject_from_pem(lets_encrypt_root_r11, "Loading Root CA");
	t0 = tx_time_get();
	printf("Calling wolfSSL_CTX_load_verify_buffer...\r\n");
	if (wolfSSL_CTX_load_verify_buffer(ctx, (const unsigned char *)lets_encrypt_root_r11,
									   strlen(lets_encrypt_root_r11), WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
		printf("wolfSSL_CTX_load_verify_buffer error\r\n");
		error_occurred = 1;
		goto cleanup;
	}
	t1 = tx_time_get();
	printf("wolfSSL_CTX_load_verify_buffer successful in %lu ticks\r\n", t1 - t0);
#endif

    printf("Setting verify mode with wolfSSL_CTX_set_verify...\r\n");
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

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
    wolfSSL_SSLSetIORecv(ssl, net_recv);
    wolfSSL_SSLSetIOSend(ssl, net_send);
    wolfSSL_SetIOReadCtx(ssl, &socket);
    wolfSSL_SetIOWriteCtx(ssl, &socket);
    printf("wolfSSL IO callbacks set successfully...\r\n");

    printf("Setting SNI using wolfSSL_UseSNI...\r\n");
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, strlen(host));
    if (ret != WOLFSSL_SUCCESS) {
		printf("❌ wolfSSL_UseSNI failed: %d\r\n", ret);
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
        printf("❌ Failed to get socket info, status: 0x%X\r\n", status);
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

void print_cert_subject_from_pem(const char* pem, const char* label)
{
    if (pem == NULL) {
        printf("❌ %s: PEM buffer is NULL\r\n", label);
        return;
    }

    WOLFSSL_X509* cert = wolfSSL_X509_load_certificate_buffer(
        (const unsigned char*)pem,
        strlen(pem),
        WOLFSSL_FILETYPE_PEM
    );

    if (cert != NULL) {
        WOLFSSL_X509_NAME* subject_name = wolfSSL_X509_get_subject_name(cert);
        char subject_str[256] = {0};

        if (wolfSSL_X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str)) != NULL) {
            printf("%s: Subject = %s\r\n", label, subject_str);
        } else {
            printf("%s: Failed to convert subject name to string\r\n", label);
        }

        wolfSSL_X509_free(cert);
    } else {
        printf("%s: Failed to parse certificate buffer\r\n", label);
    }
}

static void print_ciphers(void)
{
	char cipherList[2048];
	int len = wolfSSL_get_ciphers(cipherList, sizeof(cipherList));
	if (len > 0) {
	    printf("Supported cipher list:\r\n%s\r\n", cipherList);
	} else {
	    printf("Failed to get cipher list\r\n");
	}
}

static void tls_stream_reset(void) {
	tls_stream.buffer = tls_stream_buffer;
    tls_stream.len = 0;
    tls_stream.offset = 0;
}
