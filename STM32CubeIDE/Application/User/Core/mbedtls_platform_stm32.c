#include "mbedtls/platform_util.h"
#include "stm32h5xx_hal.h"
#include "mbedtls/platform_time.h"

mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return HAL_GetTick();  // Returns milliseconds since startup
}
