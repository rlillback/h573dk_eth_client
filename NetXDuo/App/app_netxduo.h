/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    app_netxduo.h
  * @author  MCD Application Team
  * @brief   NetXDuo applicative header file
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
#ifndef __APP_NETXDUO_H__
#define __APP_NETXDUO_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "nx_api.h"

/* Private includes ----------------------------------------------------------*/
#include "nx_stm32_eth_driver.h"

/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */
/* The DEFAULT_PAYLOAD_SIZE should match with RxBuffLen configured via MX_ETH_Init */
#ifndef DEFAULT_PAYLOAD_SIZE
#define DEFAULT_PAYLOAD_SIZE      1536
#endif

#ifndef DEFAULT_ARP_CACHE_SIZE
#define DEFAULT_ARP_CACHE_SIZE    1024
#endif

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

#define PRINT_IP_ADDRESS(addr) do { \
                                    printf("%s: %lu.%lu.%lu.%lu \r\n", #addr, \
                                    (addr >> 24) & 0xff, \
                                    (addr >> 16) & 0xff, \
                                    (addr >> 8) & 0xff, \
                                     addr& 0xff);\
                                  }while(0)
/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
UINT MX_NetXDuo_Init(VOID *memory_ptr);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
/* USER CODE BEGIN PD */

#define DEFAULT_MEMORY_SIZE       		(8 * 1024)
#define LINK_THREAD_STACK_SIZE    		2048
#define TOGGLE_LED_STACK_SIZE     		1024
#define WEB_CLIENT_THREAD_SIZE    		8192

#define TOGGLE_LED_PRIORITY              15
#define DEFAULT_PRIORITY                 5
#define LINK_PRIORITY                    11
 /*Packet payload size */
#define PACKET_PAYLOAD_SIZE              1536U
 /* APP Cache size  */
#define ARP_CACHE_SIZE                   1024U
 /* Wait option for getting @IP */
#define WAIT_OPTION                      1000
/* Entry input for Main thread */
#define ENTRY_INPUT                      0
/* Main Thread priority */
#define THREAD_PRIO                      4
/* Main Thread preemption threshold */
#define THREAD_PREEMPT_THRESHOLD         4
/* Web application size */
#define WEB_APP_SIZE                     2048U
/* Memory size */
#define MEMORY_SIZE                      2048U
// NetX Duo overhead per packet (NX_PACKET plus alignment slop)
#define NX_PACKET_METADATA_SIZE         (sizeof(NX_PACKET) + 4)
/* Size of the client packets, should match the DEFAULT_PAYLOAD_SIZE */
#define NX_PACKET_HEADER_SIZE 			 48U
#define	CLIENT_PACKET_SIZE	             1536U
/* The size of the client pool needed for HTTPS/TLS */
#define CLIENT_PACKET_COUNT              12
#define CLIENT_POOL_SIZE       			(CLIENT_PACKET_COUNT * (CLIENT_PACKET_SIZE + sizeof(NX_PACKET)))
/* Server stack */
#define CLIENT_STACK                     4096
/* SD Driver information pointer */
#define SD_DRIVER_INFO_POINTER           0
#define NULL_IP_ADDRESS                  IP_ADDRESS(0,0,0,0)
#define NX_APP_CABLE_CONNECTION_CHECK_PERIOD  (1 * NX_IP_PERIODIC_RATE)
#define NX_WEB_HTTP_PORT				 80
#define NX_WEB_HTTPS_PORT				 443
#define DHCP_TIMEOUT 					 30000
#define DNS_PACKET_SIZE 				 512
#define DNS_POOL_PACKET_COUNT           4
#define DNS_POOL_SIZE                   (DNS_POOL_PACKET_COUNT * (DNS_PACKET_SIZE + NX_PACKET_HEADER_SIZE))

/* USER CODE END PD */

#define NX_APP_DEFAULT_TIMEOUT               (10 * NX_IP_PERIODIC_RATE)

#define NX_APP_PACKET_POOL_SIZE              ((DEFAULT_PAYLOAD_SIZE + sizeof(NX_PACKET)) * 50)

#define NX_APP_THREAD_STACK_SIZE             (4 * 1024)

#define Nx_IP_INSTANCE_THREAD_SIZE           (4 * 1024)

#define NX_APP_THREAD_PRIORITY               10

#ifndef NX_APP_INSTANCE_PRIORITY
#define NX_APP_INSTANCE_PRIORITY             NX_APP_THREAD_PRIORITY
#endif

#define NX_APP_DEFAULT_IP_ADDRESS                   0

#define NX_APP_DEFAULT_NET_MASK                     0

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

#ifdef __cplusplus
}
#endif
#endif /* __APP_NETXDUO_H__ */
