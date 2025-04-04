#include "mbedtls/platform.h"
#include "stm32h5xx_hal.h"
#include "mbedtls_platform_stm32.h"

// Required typedef when using MBEDTLS_PLATFORM_MS_TIME_ALT
typedef uint32_t mbedtls_ms_time_t;

// Override mbedtls_ms_time to return HAL_GetTick()
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return HAL_GetTick();
}
