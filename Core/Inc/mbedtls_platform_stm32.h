#ifndef MBEDTLS_PLATFORM_STM32
#define MBEDTLS_PLATFORM_STM32

#include "mbedtls/platform_time.h"

#ifdef __cplusplus
extern "C" {
#endif

mbedtls_ms_time_t mbedtls_ms_time(void);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PLATFORM_STM32 */
