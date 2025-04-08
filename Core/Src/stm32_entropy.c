#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "stm32h5xx_hal.h"
#include <string.h>
#include <stdio.h>

extern RNG_HandleTypeDef hrng;

int mbedtls_hardware_poll(void *data,
						  unsigned char *output,
						  size_t len,
						  size_t *olen)
{
    printf("Entered mbedtls_hardware_poll to set entropy with %u bytes\r\n", len);
    (void) data; // unused

    uint32_t random_val;
    size_t bytes_filled = 0;

    while (bytes_filled < len) {
        if (HAL_RNG_GenerateRandomNumber(&hrng, &random_val) != HAL_OK) {
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }

        size_t copy_len = (len - bytes_filled < sizeof(random_val)) ?
                          (len - bytes_filled) : sizeof(random_val);

        memcpy(output + bytes_filled, &random_val, copy_len);
        bytes_filled += copy_len;
    }

    printf("Finished filling %u entropy bytes in mbed_tls_hardware_poll...\r\n",
           bytes_filled);
    *olen = bytes_filled;
    return 0;
} /* mbedtls_hardware_entropy_poll */
