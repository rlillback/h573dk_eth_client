#include "mbedtls/platform.h"
#include "stm32h5xx_hal.h"
#include "mbedtls_platform_stm32.h"
#include <sys/time.h>
#include <reent.h>

// Required typedef when using MBEDTLS_PLATFORM_MS_TIME_ALT
typedef uint32_t mbedtls_ms_time_t;

// Override mbedtls_ms_time to return HAL_GetTick()
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return HAL_GetTick();
}

// Implement a dummy gettimeofday function to pass compilation
// Since this STM32 doesn't have an RTC, we can't use this anyway
int gettimeofday(struct timeval *tv, void *tz)
{
    return _gettimeofday_r(NULL, tv, tz);
}

int _gettimeofday_r(struct _reent *r, struct timeval *tv, void *tz) {
    (void)r;
    (void)tz;

    if (tv) {
            tv->tv_sec = 0;
            tv->tv_usec = 0;
        }
        return 0;
}
