#ifndef MBEDTLS_PLATFORM_STM32
#define MBEDTLS_PLATFORM_STM32

#include "mbedtls/platform_time.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Required typedef for MBEDTLS_PLATFORM_MS_TIME_ALT
typedef uint32_t mbedtls_ms_time_t;

mbedtls_ms_time_t mbedtls_ms_time(void);
int gettimeofday(struct timeval *tv, void *tz);


#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PLATFORM_STM32 */
