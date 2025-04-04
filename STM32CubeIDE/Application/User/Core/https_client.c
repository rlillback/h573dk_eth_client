#include "https_client.h"
#include "mbedtls/ssl.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "nx_packet.h"
#include "nx_api.h"

#include <string.h>
#include <stdio.h>

extern NX_PACKET_POOL g_packet_pool;

static int net_send(void *ctx, const unsigned char *buf, size_t len) {
    NX_TCP_SOCKET *socket = (NX_TCP_SOCKET *)ctx;
    NX_PACKET *packet;

    if (nx_packet_allocate(&g_packet_pool, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER) != NX_SUCCESS) {
        return -1;
    }

    if (nx_packet_data_append(packet, (void *)buf, len, &g_packet_pool, NX_WAIT_FOREVER) != NX_SUCCESS) {
        nx_packet_release(packet);
        return -1;
    }

    if (nx_tcp_socket_send(socket, packet, NX_WAIT_FOREVER) != NX_SUCCESS) {
        nx_packet_release(packet);
        return -1;
    }

    return (int)len;
}

// NetX Duo to mbedTLS receive wrapper
static int net_recv(void *ctx, unsigned char *buf, size_t len) {
    NX_TCP_SOCKET *socket = (NX_TCP_SOCKET *)ctx;
    NX_PACKET *packet;
    ULONG actual_len;

    if (nx_tcp_socket_receive(socket, &packet, NX_WAIT_FOREVER) != NX_SUCCESS) return -1;
    if (nx_packet_data_extract_offset(packet, 0, buf, len, &actual_len) != NX_SUCCESS) {
        nx_packet_release(packet);
        return -1;
    }

    nx_packet_release(packet);
    return (int)actual_len;
}

int https_client_get(NX_TCP_SOCKET *socket, const char *host, const char *path) {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    const char *pers = "netx_https_client";
    char req_buffer[512];
    int ret;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("DRBG seed failed: -0x%x\n", -ret);
        goto cleanup;
    }

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf("Config defaults failed: -0x%x\n", -ret);
        goto cleanup;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        printf("SSL setup failed: -0x%x\n", -ret);
        goto cleanup;
    }

    mbedtls_ssl_set_bio(&ssl, socket, net_send, net_recv, NULL);

    if ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        printf("TLS handshake failed: -0x%x\n", -ret);
        goto cleanup;
    }

    snprintf(req_buffer, sizeof(req_buffer),
             "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);

    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)req_buffer, strlen(req_buffer))) < 0) {
        printf("SSL write failed: -0x%x\n", -ret);
        goto cleanup;
    }

    unsigned char resp_buf[512];
    do {
        ret = mbedtls_ssl_read(&ssl, resp_buf, sizeof(resp_buf) - 1);
        if (ret > 0) {
            resp_buf[ret] = '\0';
            printf("%s", resp_buf);
        }
    } while (ret > 0);

cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}
