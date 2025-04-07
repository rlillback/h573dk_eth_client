#ifndef __STM32_ENTROPY_H__
#define __STM32_ENTROPY_H__

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

#endif /* __STM32_ENTROPY_H__ */
