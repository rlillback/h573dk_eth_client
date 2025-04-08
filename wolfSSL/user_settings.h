#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define STM32H563xx

#include "user_settings_stm32.h"
#include "time.h"

/* Turn on some extensions */
#define HAVE_ALPN
#define WOLFSSL_NO_ASN_STRICT

/* Turn off the low level ASM cortex-M3+ optimizations */
/* These don't work with the STM32H573I-DK, as the M33 */
/* architecture is different and this causes a hard fault */
#undef WOLFSSL_SP_ASM
#undef WOLFSSL_SP_ARM_CORTEX_M_ASM

/* Required for ThreadX */
#define WOLFSSL_THREADX
#define SINGLE_THREADED
#define WOLFSSL_USER_MUTEX

/* Cert & ASN.1 support */
#define HAVE_X509
#define HAVE_X509_CERT
#define WOLFSSL_CERT_EXT
#define WOLFSSL_ASN
#define WOLFSSL_BASE64_ENCODE
#define HAVE_CERTIFICATE_BUFFER
#define WOLFSSL_SMALL_CERT_VERIFY
#define HAVE_CERTIFICATE_VERIFY
#define WOLFSSL_CERT_EXT
#define HAVE_AESGCM
#define WOLFSSL_CERT_REQ
#define OPENSSL_EXTRA

#define WOLFSSL_MAX_RSA_BITS 8192
#define SP_INT_BITS 8192
#define FP_MAX_BITS 8192
#define WOLFSSL_SP_4096


/* Buffer and heap management */
#define WOLFSSL_MAX_CHAIN_DEPTH 4

/* Debugging output (optional) */
#define DEBUG_WOLFSSL
#define WOLFSSL_DEBUG_MATH
#define WOLFSSL_CUSTOM_ALLOCATORS
#define WOLFSSL_DEBUG_LEVEL 6

/* Override printf and other I/O functions for embedded systems */
#define WOLFSSL_USER_PRINTF         printf
#define WOLFSSL_USER_MEMCPY         memcpy
#define WOLFSSL_USER_MEMSET         memset

#endif /* WOLFSSL_USER_SETTINGS_H */
