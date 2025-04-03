#include "mbedtls/platform_util.h"
#include "stm32h5xx_hal.h"

unsigned long mbedtls_ms_time(void)
{
    return HAL_GetTick();  // Returns milliseconds since startup
}