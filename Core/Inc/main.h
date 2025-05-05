/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32h5xx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "stdio.h"
/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define LED_GREEN_Pin GPIO_PIN_9
#define LED_GREEN_GPIO_Port GPIOI
#define LED_RED_Pin GPIO_PIN_1
#define LED_RED_GPIO_Port GPIOF

/* USER CODE BEGIN Private defines */
#undef  __HTTP_ONLY__
#undef  __USE_ONE_WAY_TLS__
#define __USE_MTLS__

// CA Certificate roots to load
#undef  __LOAD_AMAZON_CA__
#undef  __LOAD_DIGICERT_CA__
#define __LOAD_ENTRUST_CA__

// TLS Configurations
#define TLS_HEADER_SIZE 5
#define MAX_TLS_RECORD_SIZE (16 * 1024)
#define HTTPS_TIMEOUT 3000
#define MAX_REQUEST_LEN 512
#define TLS_MAX_RETRIES 200
#define TLS_SLEEP_TICKS 5

#if !defined(WOLFSSL_DEBUG_LEVEL)
	#define WOLFSSL_DEBUG_LEVEL 6
#endif

// Optional debug toggles
#undef  __MSS_PACKET_DUMP__				/* What is coming across the wire in the 1460 byte packets */
#undef  __DUMP_WOLFSSL_PACKETS__        /* What is sent from the net_recv function to wolfSSL */
#undef  __PRINT_ALLOCATIONS__           /* Print every wolfSSL malloc and free */
#undef  __PRINT_WOLF_SSL_DEBUG__        /* Print the internal wolfSSL debug stuff up to level 3 */
#undef  __PRINT_HTTPS_RESPONSES__       /* Print the responses from HTTP */
#undef  __PRINT_NET_RECV_DATA__         /* Print the data inside of the net_recv -- good for seeing if memory is big enough */
#undef  __DUMP_CLIENT_PACKET_POOL__     /* Print the http client packet pool to see if we are running out of pool space */
/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */
