/**
 * \file mbedtls/build_info.h
 *
 * \brief Build-time configuration info
 *
 *  Include this file if you need to depend on the
 *  configuration options defined in mbedtls_config.h or MBEDTLS_CONFIG_FILE
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 */

#ifndef MBEDTLS_BUILD_INFO_H
#define MBEDTLS_BUILD_INFO_H

/*
 * This set of compile-time defines can be used to determine the version number
 * of the Mbed TLS library used. Run-time variables for the same can be found in
 * version.h
 */

/**
 * The version number x.y.z is split into three parts.
 * Major, Minor, Patchlevel
 */
#define MBEDTLS_VERSION_MAJOR  3
#define MBEDTLS_VERSION_MINOR  6
#define MBEDTLS_VERSION_PATCH  2

/**
 * The single version number has the following structure:
 *    MMNNPP00
 *    Major version | Minor version | Patch version
 */
#define MBEDTLS_VERSION_NUMBER         0x03060200
#define MBEDTLS_VERSION_STRING         "3.6.2"
#define MBEDTLS_VERSION_STRING_FULL    "Mbed TLS 3.6.2"

/* mbed TLS build configuration generated for STM32H573 NetX Duo HTTPS client */

/* Platform support */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_PLATFORM_TIME_ALT

/* System headers */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* Core modules */
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_GCM_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* TLS features */
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_COOKIE_C

/* Key exchange algorithms */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

#endif /* MBEDTLS_BUILD_INFO_H */
