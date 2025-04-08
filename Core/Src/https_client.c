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
#include "mbedtls/pem.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ecp.h"
#include "tx_api.h"
#include "main.h"
#include "stm32_entropy.h"
#include "root_pems.h"

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

// Local variables
__attribute__((aligned(8))) static char cert_copy[2048];

void mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) {
    printf("%s:%04d: %s\r\n", file, line, str);
}

static int required_curve_bits(const mbedtls_ssl_ciphersuite_t *suite) {
    switch (suite->cipher) {
        case MBEDTLS_CIPHER_AES_128_GCM:
        case MBEDTLS_CIPHER_AES_128_CBC:
        case MBEDTLS_CIPHER_AES_128_CCM:
            return 256;

        case MBEDTLS_CIPHER_AES_256_GCM:
        case MBEDTLS_CIPHER_AES_256_CBC:
        case MBEDTLS_CIPHER_AES_256_CCM:
            return 384;

        default:
            return 0; // Allow all curves if cipher type is unrecognized
    }
}


void print_ciphers(const int *ciphers) {
    const mbedtls_ssl_ciphersuite_t *suite;
    const mbedtls_cipher_info_t *info;
    const mbedtls_ecp_curve_info *curve;

    while (*ciphers) {
        suite = mbedtls_ssl_ciphersuite_from_id(*ciphers);
        if (!suite) {
            printf("   Cipher: 0x%04X = [Unknown suite ID]\r\n", *ciphers);
            ciphers++;
            continue;
        }

        info = mbedtls_cipher_info_from_type(suite->cipher);
        const char *ready_str = info ? "READY" : "MISSING";

        printf("   Cipher: 0x%04X = %-45s  kx=%d  mac=%d  [%s]",
               *ciphers,
               suite->name,
               suite->key_exchange,
               suite->mac,
               ready_str);

        // Show only if ECC-based key exchange
        if (suite->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_RSA ||
            suite->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA ||
            suite->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDH_RSA ||
            suite->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA) {

            int min_curve_bits = required_curve_bits(suite);
            printf("\r\n      Usable curves (≥ %d bits):\r\n", min_curve_bits);

            int found = 0;
            for (curve = mbedtls_ecp_curve_list(); curve->grp_id != 0; curve++) {
                if (curve->bit_size >= min_curve_bits) {
                    printf("         - %s (%d bits)\r\n", curve->name, curve->bit_size);
                    found = 1;
                }
            }

            if (!found) {
                printf("         [None available]\r\n");
            }
        }

        printf("\r\n");
        ciphers++;
    }
}


void print_cert_ascii(const char *cert, size_t len) {
	for (int i = 0; i < len; i++) {
	    printf("%02X ", cert[i]);
	    if (i % 16 == 15) printf("\r\n");
	}
}

// Convert milliseconds to ThreadX ticks, rounding up to avoid zero
static ULONG ms_to_ticks_rounded_up(UINT ms) {
    if (ms == 0) return 0;
    return (TX_TIMER_TICKS_PER_SECOND * (ULONG)ms + 999U) / 1000U;
}

// Set the intermediate and final delays (in milliseconds)
static void threadx_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms) {
    mbedtls_threadx_timer_ctx *tctx = (mbedtls_threadx_timer_ctx *) ctx;

    // Some buggy servers/libraries set 0,0 early — ignore that and keep timer running
    if (int_ms == 0 && fin_ms == 0 && tctx->timer_active == 0) {
        printf("threadx_set_timer: ignored initial 0,0\r\n");
        return;
    }

    if (int_ms == 0 && fin_ms == 0) {
        tctx->timer_active = 0;
        printf("threadx_set_timer: DISABLED (int_ms=0, fin_ms=0)\r\n");
        return;
    }

    // Convert ms to ticks, rounding up
    tctx->intermediate_delay = ms_to_ticks_rounded_up(int_ms);
    tctx->final_delay        = ms_to_ticks_rounded_up(fin_ms);

    if (int_ms > 0 && tctx->intermediate_delay == 0) tctx->intermediate_delay = 1;
    if (fin_ms > 0 && tctx->final_delay == 0)        tctx->final_delay        = 1;

    tctx->start_time   = tx_time_get();
    tctx->timer_active = 1;

    printf("threadx_set_timer: int=%lu ticks, fin=%lu ticks (from int_ms=%lu, fin_ms=%lu)\r\n",
           tctx->intermediate_delay, tctx->final_delay,
           (ULONG)int_ms, (ULONG)fin_ms);
}

// Get timer state:
//   -1: expired
//    0: ongoing
//    1: intermediate delay passed
static int threadx_get_timer(void *ctx) {
    mbedtls_threadx_timer_ctx *tctx = (mbedtls_threadx_timer_ctx *) ctx;

    if (!tctx->timer_active) {
        printf("threadx_get_timer: INACTIVE\r\n");
        return -1;
    }

    ULONG now     = tx_time_get();
    ULONG elapsed = now - tctx->start_time;

    if (elapsed >= tctx->final_delay) {
        tctx->timer_active = 0;
        printf("threadx_get_timer: EXPIRED (%lu >= %lu)\r\n", elapsed, tctx->final_delay);
        return -1;
    }

    if (elapsed >= tctx->intermediate_delay) {
        printf("threadx_get_timer: INTERMEDIATE PASSED (%lu >= %lu)\r\n", elapsed, tctx->intermediate_delay);
        return 1;
    }

    printf("threadx_get_timer: ONGOING (%lu < %lu)\r\n", elapsed, tctx->intermediate_delay);
    return 0;
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
    size_t der_len = 0;
    mbedtls_pem_context pem;
    char err_buf[512];

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
    printf("Hostname %s returned and IP Address of ", host);
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

    // enable mbedTLS debug output
    mbedtls_ssl_conf_dbg(&conf, mbedtls_debug, NULL);
    mbedtls_debug_set_threshold(4);

    // Add Entropy Source
    printf("Adding entropy source via mbedtls_entropy_add_source...\r\n");
	retval = mbedtls_entropy_add_source(&entropy,
									 mbedtls_hardware_poll,
									 NULL,
									 32, // Minimum bytes of entropy (usually 32)
									 MBEDTLS_ENTROPY_SOURCE_STRONG);
	if (retval != 0) {
		mbedtls_strerror(retval, err_buf, sizeof(err_buf));
		printf("mbedtls_entropy_add_source failed: -0x%X (%s)\r\n", -retval, err_buf);
		goto cleanup;
	}
	printf("mbedtls_entropy_add_source successful...\r\n");

	// Initialize Root CA
	printf("Initializing cert chain and adding trusted certificate...\r\n");
	printf("Copying the certificate into RAM using an aligned (4) RAM variable...\r\n");
	memset(cert_copy, 0, sizeof(cert_copy));
	memcpy(cert_copy, amazon_root_ca1_pem, strlen(amazon_root_ca1_pem) + 1);
	printf("Cert string length: %lu\r\n", (unsigned long)strlen(cert_copy));

	// Read the PEM and convert to DER
	printf("Using mbedtls_pem_read_buffer....\r\n");
	mbedtls_pem_init(&pem);
	retval = mbedtls_pem_read_buffer(&pem,
	                                  "-----BEGIN CERTIFICATE-----",
	                                  "-----END CERTIFICATE-----",
	                                  (const unsigned char *)cert_copy,
	                                  NULL, 0, &der_len);
    if (retval != 0) {
		mbedtls_strerror(retval, err_buf, sizeof(err_buf));
		printf("mbedtls_pem_read_buffer parse failed: -0x%x (%s)\r\n", -retval, err_buf);
		Error_Handler();
    }
	printf("mbedtls_pem_read_buffer decode ret: %d, len: %d\r\n", retval, pem.buflen);

	// Store the DER into the ca_cert variable
    mbedtls_x509_crt_init(&ca_cert);
    retval = mbedtls_x509_crt_parse_der(&ca_cert, pem.buf, pem.buflen);

    if (retval != 0) {
    	mbedtls_strerror(retval, err_buf, sizeof(err_buf));
    	printf("mbedtls_x509_crt_parse_der parse failed: -0x%x (%s)\r\n", -retval, err_buf);
        Error_Handler();
    }
    printf("mbedtls_x509_crt_parse_der succeeded..\r\n");

    // Configure the CA Chain
    mbedtls_ssl_conf_ca_chain(&conf, &ca_cert, NULL);

    // Seed the DRBG from the entropy
    printf("Seeding DRBG via mbedtls_ctr_drbg_seed...\r\n");
    retval = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                mbedtls_entropy_func,
                                &entropy,
                                (const unsigned char *)pers,
                                strlen(pers));
    if (retval != 0) {
    	mbedtls_strerror(retval, err_buf, sizeof(err_buf));
        printf("DRBG seed failed: -0x%X (%s)\r\n", -retval, err_buf);
        Error_Handler();
    }
    printf("DRBG seed successful....\r\n");

    const char *alpn[] = { "http/1.1", NULL };
    mbedtls_ssl_conf_alpn_protocols(&conf, alpn);

    // COnfigure the SSL defaults
    printf("mbedtls_ssl_config_defaults being called...\r\n");
    retval = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (retval != 0) {
    	mbedtls_strerror(retval, err_buf, sizeof(err_buf));
        printf("mbedtls_ssl_config_defaults failed: -0x%X (%s)\r\n", -retval, err_buf);
        Error_Handler();
    }
    printf("mbedtls_ssl_config_defaults successful...\r\n");

    mbedtls_ssl_conf_max_frag_len(&conf, MBEDTLS_SSL_MAX_FRAG_LEN_1024);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    printf("Setting default ciphersuites to be:\r\n");
    int *ciphers = (int *)mbedtls_ssl_list_ciphersuites();
    print_ciphers(ciphers);
    mbedtls_ssl_conf_ciphersuites(&conf, (const int *)ciphers);
    printf("All the ciphers were set as:\r\n");
    ciphers = (int *)*conf.ciphersuite_list;
    print_ciphers(ciphers);

    printf("Setting host name to %s using mbedtls_ssl_set_hostname...\r\n", host);
    retval = mbedtls_ssl_set_hostname(&ssl, host);
    if (retval != 0) {
    	mbedtls_strerror(retval, err_buf, sizeof(err_buf));
		printf("mbedtls_ssl_set_hostname failed: -0x%X (%s)\r\n", -retval, err_buf);
		Error_Handler();
	}
	printf("mbedtls_ssl_set_hostname successful...\r\n");

    retval = mbedtls_ssl_setup(&ssl, &conf);
    if (retval != 0) {
    	mbedtls_strerror(retval, err_buf, sizeof(err_buf));
        printf("ssl_setup failed: -0x%X (%s)\r\n", -retval, err_buf);
        Error_Handler();
    }
    printf("mbedtls_ssl_setup successful...\r\n");

    printf("Registering callback via mbedtls_ssl_set_threadx_timer_cb...\r\n");
    mbedtls_ssl_set_threadx_timer_cb(&ssl);

    mbedtls_ssl_set_bio(&ssl, &socket, net_send, net_recv, NULL);
    printf("mbedtls_ssl_set_bio finished...\r\n");

    // ✅ Check that socket is connected
    if (socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) {
        printf("Socket is not connected (state = 0x%x)\r\n", socket.nx_tcp_socket_state);
        Error_Handler();
    }
    printf("Socket is connected...\r\n");

    // TLS handshake
    printf("Authmode is: %d\r\n", conf.authmode);
    retval = mbedtls_ssl_handshake(&ssl);
    if (retval != 0) {
    	mbedtls_strerror(retval, err_buf, sizeof(err_buf));
    	printf("Failed mbedtls_ssl_handshake with code  -0x%X (%s)\r\n", -retval, err_buf);

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
    	mbedtls_strerror(retval, err_buf, sizeof(err_buf));
        printf("mbedtls_ssl_write failed: -0x%X (%s)\r\n", -retval, err_buf);
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
