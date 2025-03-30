/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    app_netxduo.c
  * @author  MCD Application Team
  * @brief   NetXDuo applicative file
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

/* Includes ------------------------------------------------------------------*/
#include "app_netxduo.h"

/* Private includes ----------------------------------------------------------*/
#include "nxd_dhcp_client.h"
/* USER CODE BEGIN Includes */
#include "app_filex.h"
#include "main.h"
#include "nxd_dhcp_client.h"
#include "tx_thread.h"
#include "nx_stm32_eth_config.h"
#include "fx_api.h"
#include "nx_port.h"
#include "nx_api.h"
#include "nx_web_http_client.h"
#include "nxd_dns.h"
#include <inttypes.h>
#include "stm32h5xx_hal.h"
#include "stm32h5xx_hal_eth.h"
#include "stm32h5xx_hal_gpio.h"
#include "stm32h5xx_hal_rcc.h"
#include "stm32h5xx_hal_cortex.h"
#include "stm32h5xx_hal_uart.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
TX_THREAD      NxAppThread;
NX_PACKET_POOL NxAppPool;
NX_IP          NetXDuoEthIpInstance;
TX_SEMAPHORE   DHCPSemaphore;
NX_DHCP        DHCPClient;
/* USER CODE BEGIN PV */
NX_DNS 		   DnsClient;
/* Define the ThreadX , NetX and FileX object control blocks. */
/* Define Threadx global data structures. */
TX_THREAD HttpClientThread;
TX_THREAD AppLinkThread;
TX_THREAD LedThread;
/* Define NetX global data structures. */
NX_PACKET_POOL ClientPacketPool;
ULONG IpAddress;
ULONG NetMask;
ULONG free_bytes;
/* App memory pointer. */
CHAR   *pointer;
NX_WEB_HTTP_CLIENT HTTPClient;

static uint8_t client_packet_pool_area[CLIENT_POOL_SIZE];

#undef __COMPILE_SERVER__

/* Define FileX global data structures. */
/* the server reads the content from the uSD, a FX_MEDIA instance is required */
FX_MEDIA                SDMedia;
/* Buffer for FileX FX_MEDIA sector cache. this should be 32-Bytes aligned to avoid
   cache maintenance issues */
ALIGN_32BYTES (uint32_t DataBuffer[512]);
/* Buffer for FileX FX_MEDIA sector cache. this should be 4-bytes aligned to avoid
   unaligned access issues */
uint32_t DataBuffer[512];

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
static VOID nx_app_thread_entry (ULONG thread_input);  // The main application
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr); // Check for ip address change

/* USER CODE BEGIN PFP */
static VOID nx_client_thread_entry(ULONG thread_input); // the HTTP client
static VOID app_link_thread_entry(ULONG thread_input); // Check that the Ethernet link exists
static VOID led_thread_entry(ULONG thread_input); // Blink the green LED every 1/2 second
void dhcp_client_callback(NX_DHCP *dhcp_client, UINT status);
uint32_t check_phy_link_status(VOID);
/* USER CODE END PFP */

/**
  * @brief  Application NetXDuo Initialization.
  * @param memory_ptr: memory pointer
  * @retval int
  */
UINT MX_NetXDuo_Init(VOID *memory_ptr)
{
  UINT ret = NX_SUCCESS;
  TX_BYTE_POOL *byte_pool = (TX_BYTE_POOL*)memory_ptr;

   /* USER CODE BEGIN App_NetXDuo_MEM_POOL */
  UINT state;
    (void)byte_pool;
    printf("h573dk_https_eth_client started...\r\n");
    check_phy_link_status();
    /* Print the available byte pool */
    CHAR *dummy_name;
    TX_THREAD *dummy_ptr;
    ULONG dummy_count;
    TX_BYTE_POOL *dummy_next;
    ULONG available, fragments;

    tx_byte_pool_info_get(byte_pool,
                          &dummy_name,
                          &available,
                          &fragments,
                          &dummy_ptr,
                          &dummy_count,
                          &dummy_next);
    printf("Byte pool available: %lu bytes in %lu fragments\r\n", available, fragments);
    printf("Thread priorities are:\r\n");
    printf("\tNX_APP_THREAD_PRIORITY = %u\r\n", NX_APP_THREAD_PRIORITY);
    printf("\tDEFAULT_PRIORITY       = %u\r\n", DEFAULT_PRIORITY);
    printf("\tLINK_PRIORITY          = %u\r\n", LINK_PRIORITY);
    printf("\tTOGGLE_LED_PRIORITY    = %u\r\n", TOGGLE_LED_PRIORITY);
    printf("NX_APP_THREAD_STACK_SIZE = %u\r\n", NX_APP_THREAD_STACK_SIZE);
  /* USER CODE END App_NetXDuo_MEM_POOL */

  /* USER CODE BEGIN 0 */
  /******************************************************************************************/
  /* NOTE: DO NOT LET  IOC regenerate this function! */
  /******************************************************************************************/

  /* Initialize the NetXDuo system. */
  CHAR *pointer;
  nx_system_initialize();

    /* Allocate the memory for packet_pool.  */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, NX_APP_PACKET_POOL_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the Packet pool to be used for packet allocation,
   * If extra NX_PACKET are to be used the NX_APP_PACKET_POOL_SIZE should be increased
   */
  printf("Allocating memory for the packet pool...\r\n");
  ret = tx_byte_allocate(byte_pool, (VOID **) &pointer, NX_APP_PACKET_POOL_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
   printf("tx_byte_allocate for packet pool failed: 0x%02X\r\n", ret);
    return TX_POOL_ERROR;
  }

  /* Allocate the memory for Ip_Instance */
  printf("Allocating memory for the IP Instance...\r\n");
  ret = tx_byte_allocate(byte_pool, (VOID **) &pointer, Nx_IP_INSTANCE_THREAD_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
	printf("tx_byte_allocate for packet pool failed: 0x%02X\r\n", ret);
    return TX_POOL_ERROR;
  }

  /* Create the main NX_IP instance */
  printf("Creating the main NetX IP instance...\r\n");
  ret = nx_ip_create(&NetXDuoEthIpInstance, "NetX Ip instance", NX_APP_DEFAULT_IP_ADDRESS, NX_APP_DEFAULT_NET_MASK, &NxAppPool, nx_stm32_eth_driver,
                     pointer, Nx_IP_INSTANCE_THREAD_SIZE, NX_APP_INSTANCE_PRIORITY);

  if (ret != NX_SUCCESS)
  {
	printf("nx_ip_create failed: 0x%02X\r\n", ret);
    return NX_NOT_SUCCESSFUL;
  }

  /* Allocate the memory for ARP */
  printf("Allocating memory for ARP...\r\n");
  ret = tx_byte_allocate(byte_pool, (VOID **) &pointer, DEFAULT_ARP_CACHE_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
	printf("tx_byte_allocate for ARP failed: 0x%02X\r\n", ret);
    return TX_POOL_ERROR;
  }

  /* Enable the ARP protocol and provide the ARP cache size for the IP instance */

  /* USER CODE BEGIN ARP_Protocol_Initialization */
  printf("Enable the ARP protocol...\r\n");
  /* USER CODE END ARP_Protocol_Initialization */
  ret = nx_arp_enable(&NetXDuoEthIpInstance, (VOID *)pointer, DEFAULT_ARP_CACHE_SIZE);
  if (ret != NX_SUCCESS)
  {
	printf("nx_arp_enable failed: 0x%02X\r\n", ret);
    return NX_NOT_SUCCESSFUL;
  }

  /* Enable the ICMP */

  /* USER CODE BEGIN ICMP_Protocol_Initialization */
  printf("Enabling ICMP...\r\n");
  /* USER CODE END ICMP_Protocol_Initialization */

  ret = nx_icmp_enable(&NetXDuoEthIpInstance);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_SUCCESSFUL;
  }

  /* Enable TCP Protocol */

  /* USER CODE BEGIN TCP_Protocol_Initialization */

  /* USER CODE END TCP_Protocol_Initialization */
  ret = nx_tcp_enable(&NetXDuoEthIpInstance);

  if (ret != NX_SUCCESS)
  {
	printf("nx_tcp_enable failed: 0x%02X\r\n", ret);
    return NX_NOT_SUCCESSFUL;
  }

  /* Enable the UDP protocol required for  DHCP communication */

  /* USER CODE BEGIN UDP_Protocol_Initialization */
  printf("Enabling UDP...\r\n");
  /* USER CODE END UDP_Protocol_Initialization */
  ret = nx_udp_enable(&NetXDuoEthIpInstance);

  if (ret != NX_SUCCESS)
  {
 	printf("nx_udp_enable failed: 0x%02X\r\n", ret);
    return NX_NOT_SUCCESSFUL;
  }

  /* Allocate the memory for main thread   */
  printf("Allocating memory for the main thread...\r\n");
  ret = tx_byte_allocate(byte_pool, (VOID **) &pointer, NX_APP_THREAD_STACK_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
	printf("tx_byte_allocate for the main thread failed: 0x%02X\r\n", ret);
    return TX_POOL_ERROR;
  }

  /* Create the main thread */
  /* USER CODE BEGIN MAIN THREAD CREATION */
  printf("Creating the main NetXDuo App thread...\r\n");
  /* USER CODE END MAIN THREAD CREATION */
  ret = tx_thread_create(&NxAppThread,
		  "NetXDuo App thread",
		  nx_app_thread_entry ,
		  0,
		  pointer,
		  NX_APP_THREAD_STACK_SIZE,
          NX_APP_THREAD_PRIORITY,
		  NX_APP_THREAD_PRIORITY,
		  TX_NO_TIME_SLICE,
		  TX_AUTO_START);

  if (ret != TX_SUCCESS)
  {
	printf("tx_thread_create for the main thread failed: 0x%02X\r\n", ret);
    return TX_THREAD_ERROR;
  }
  printf("NxAppThread created, return code: 0x%02X\r\n", ret);

  /* Create the DHCP client */

  /* USER CODE BEGIN DHCP_Protocol_Initialization */
  /* NOTE: We are also going to use this USER CODE section to hide some of the thread initializations we need for our application */
  /* BEGIN KEYFACTOR CODE */

  /* Allocate the TCP client thread stack. */
  printf("Allocating memory for HTTP client thread.\r..\n");
  ret = tx_byte_allocate(byte_pool, (VOID **) &pointer, 2 * DEFAULT_MEMORY_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
	printf("tx_byte_allocate failed: 0x%02X\r\n", ret);
    return TX_POOL_ERROR;
  }
  /* create the HTTP client thread */
  printf("Creating the HTTP client thread...\r\n");
  ret = tx_thread_create(&HttpClientThread, "App Client Thread", nx_client_thread_entry, 0, pointer, 2 * DEFAULT_MEMORY_SIZE,
                         DEFAULT_PRIORITY, DEFAULT_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);
   if (ret != TX_SUCCESS)
  {
	printf("tx_thread_create failed: 0x%02X\r\n", ret);
    return TX_THREAD_ERROR;
  }
  printf("HttpClientThread created, return code: 0x%02X\r\n", ret);

  tx_thread_info_get(&HttpClientThread, NX_NULL, &state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
  printf("HttpClientThread initial state: %u\r\n", state);

  /* Allocate the memory for toggle green led thread */
  printf("Allocating memory for the Green LED thread...\r\n");
  ret = tx_byte_allocate(byte_pool, (VOID **) &pointer, DEFAULT_MEMORY_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
	printf("tx_byte_allocate failed: 0x%02X\r\n", ret);
    return TX_POOL_ERROR;
  }
  /* create the LED control thread */
  printf("Creating the Green LED control thread...\r\n");
  ret = tx_thread_create(&LedThread, "LED control Thread", led_thread_entry, 0, pointer, DEFAULT_MEMORY_SIZE,
                         TOGGLE_LED_PRIORITY, TOGGLE_LED_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);
  if (ret != TX_SUCCESS)
  {
	printf("tx_thread_create failed: 0x%02X\r\n", ret);
    return TX_THREAD_ERROR;
  }
  printf("LedThread created, return code: 0x%02X\r\n", ret);

  /* Allocate the memory for Ethernet Link Check thread */
  printf("Allocating memory for the Ethernet Link Check thread...\r\n");
  ret = tx_byte_allocate(byte_pool, (VOID **) &pointer,2 *  DEFAULT_MEMORY_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
	printf("tx_byte_allocate failed: 0x%02X\r\n", ret);
    return TX_POOL_ERROR;
  }
  /* create the Link thread */
  printf("Creating the Ethernet Link Check thread...\r\n");
  ret = tx_thread_create(&AppLinkThread, "App Eth Link Thread", app_link_thread_entry, 0, pointer, 2 * DEFAULT_MEMORY_SIZE,
                         LINK_PRIORITY, LINK_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);
  if (ret != TX_SUCCESS)
  {
	printf("tx_thread_create failed: 0x%02X\r\n", ret);
    return TX_THREAD_ERROR;
  }
  printf("AppLinkThread created, return code: 0x%02X\r\n", ret);

  /* Create the client packet pool. Don't need to allocate it, as we already defined it as a static buffer. */
  printf("Creating the HTTP client packet pool...\r\n");
  ret = nx_packet_pool_create(&ClientPacketPool, "HTTP Client Packet Pool",
                              CLIENT_PACKET_SIZE,
                              client_packet_pool_area, CLIENT_POOL_SIZE);
  if (ret != NX_SUCCESS)
  {
	printf("nx_packet_pool_create failed: 0x%02X\r\n", ret);
    return NX_NOT_SUCCESSFUL;
  }

  /* Establish the DNS Client */
  printf("Establishing the DNS client...\r\n");
#ifndef DNS_SERVER_ADDRESS
#define DNS_SERVER_ADDRESS IP_ADDRESS(8,8,8,8)
#endif
  nx_dns_create(&DnsClient, &NetXDuoEthIpInstance, (UCHAR *)"DNS Client");
  nx_dns_server_add(&DnsClient, DNS_SERVER_ADDRESS);
  /* END KEYFACTOR CODE */

  /* Start the standard DHCP Client -  this won't be auto-regenerated so be careful here */
  printf("Enabling DHCP Client...\r\n");
  ret = nx_dhcp_create(&DHCPClient, &NetXDuoEthIpInstance, "DHCP Client");
  if (ret != NX_SUCCESS)
  {
	printf("nx_dhcp_create failed: 0x%02X\r\n", ret);
    return NX_DHCP_ERROR;
  }
  printf("DHCP Client created successfully.\r\n");
 /* USER CODE END DHCP_Protocol_Initialization */

  /* set DHCP notification callback  */
  printf("Creating DHCP Semaphore...\r\n");
  tx_semaphore_create(&DHCPSemaphore, "DHCP Semaphore", 0);

  /* USER CODE BEGIN MX_NetXDuo_Init */

#undef __DEBUG_THREAD_START__
#ifdef __DEBUG_THREAD_START__
  UINT resume_ret = tx_thread_resume(&NxAppThread);
  printf("Manual resume of NxAppThread returned: 0x%02X\r\n", resume_ret);
#endif

#define __CHECK_THREAD_STATES__
#ifdef __CHECK_THREAD_STATES__
  UINT thread_state;
  tx_thread_info_get(&NxAppThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
  printf("NxAppThread state: 0x%02X\r\n", thread_state);

  tx_thread_info_get(&HttpClientThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
  printf("HttpClientThread state: 0x%02X\r\n", thread_state);

  tx_thread_info_get(&AppLinkThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
  printf("AppLinkThread state: 0x%02X\r\n", thread_state);

  tx_thread_info_get(&LedThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
  printf("LedThread state: 0x%02X\r\n", thread_state);
#endif

  printf("Got to the end of the MX_NetXDuo_Init function with return code = 0x%02X\r\n", ret);
  __enable_irq();  // Sanity check for interrupts being enabled

  /******************************************************************************************/
  /* END OF NOTE: DO NOT LET  IOC regenerate this function! */
  /******************************************************************************************/
  /* USER CODE END 0 */

  /* USER CODE BEGIN MX_NetXDuo_Init */
  /* USER CODE END MX_NetXDuo_Init */

  return ret;
} /* MX_NetXDuo_Init */

/**
* @brief  ip address change callback.
* @param ip_instance: NX_IP instance
* @param ptr: user data
* @retval none
*/
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr)
{
  /* USER CODE BEGIN ip_address_change_notify_callback */
  printf("Entered ip_address_change_notify_callback...\r\n");
  if (nx_ip_address_get(&NetXDuoEthIpInstance, &IpAddress, &NetMask) != NX_SUCCESS)
  {
    /* USER CODE BEGIN ip address change callback error */
	printf("Failed to get nx_ip_address_get...\r\n");
    /* Error, call error handler. */
    Error_Handler();

    /* USER CODE END ip address change callback error */
  }
  if(IpAddress != NULL_IP_ADDRESS)
  {
    tx_semaphore_put(&DHCPSemaphore);
  }
  /* USER CODE END ip_address_change_notify_callback */
} /* ip_address_change_notify_callback */

/**
* @brief  Main thread entry.
* @param thread_input: ULONG user argument used by the thread entry
* @retval none
*/
static VOID nx_app_thread_entry (ULONG thread_input)
{
  /* USER CODE BEGIN Nx_App_Thread_Entry 0 */
  printf("Entered nx_app_thread_entry...\r\n");
  __enable_irq();  // Sanity check for interrupts being enabled
  /* USER CODE END Nx_App_Thread_Entry 0 */

  UINT ret = NX_SUCCESS;

  /* USER CODE BEGIN Nx_App_Thread_Entry 1 */

  /* register the IP address change callback */
  printf("Configure nx_ip_address_change_notify...\r\n");
  ret = nx_ip_address_change_notify(&NetXDuoEthIpInstance, ip_address_change_notify_callback, NULL);
  if (ret != NX_SUCCESS)
  {
    /* USER CODE BEGIN IP address change callback error */
    printf("nx_ip_address_change_notify failed: 0x%02X\r\n", ret);
    /* Error, call error handler. */
    Error_Handler();
    /* USER CODE END IP address change callback error */
  }
  printf("nx_ip_address_change_notify succeeded with code = 0x%02X\r\n", ret);

  /* start the DHCP client */
  printf("Configure start DHCP client...\r\n");
  ret = nx_dhcp_start(&DHCPClient);
  if (ret != NX_SUCCESS)
  {
    /* USER CODE BEGIN DHCP client start error */
  	printf("nx_ip_address_change_notify failed: 0x%02X\r\n", ret);
  	/* Error, call error handler. */
  	Error_Handler();
    /* USER CODE END DHCP client start error */
  }
  printf("nx_dhcp_start succeeded with code = 0x%02X\r\n", ret);

  /* wait until an IP address is ready */
  printf("Waiting until an IP address is ready...tx_semaphore_get....\r\n");
  ret = tx_semaphore_get(&DHCPSemaphore, DHCP_TIMEOUT);
  if(ret != TX_SUCCESS)
  {
    /* USER CODE BEGIN DHCPSemaphore get error */
 	printf("DHCPSemaphore get error: 0x%02X\r\n", ret);
  	while(1) { };
    /* USER CODE END DHCPSemaphore get error */
  }

  /* wait until an IP address is ready */
  printf("Waiting until an IP address is ready...tx_semaphore_get....\r\n");
  ret = tx_semaphore_get(&DHCPSemaphore, DHCP_TIMEOUT);
  if(ret != TX_SUCCESS)
  {
    /* USER CODE BEGIN DHCPSemaphore get error */
	printf("DHCPSemaphore get error: 0x%02X\r\n", ret);
	Error_Handler();
	while(1) { };
    /* USER CODE END DHCPSemaphore get error */
  }
  else
  {
    printf("Received DHCP semaphore, IP address is ready.\r\n");
  }

  nx_ip_address_get(&NetXDuoEthIpInstance, &IpAddress, &NetMask);
  PRINT_IP_ADDRESS(IpAddress);

  /* the network is correctly initialized, start the WEB client thread */
  printf("DHCP complete. Starting HTTP client thread...\r\n");
  ret = tx_thread_resume(&HttpClientThread);
  printf("tx_thread_resume returned: 0x%02X\r\n", ret);


  /* this thread is not needed any more, we relinquish it */
  printf("Relinquishing nx_app_thread_entry as it is not required anymore...\r\n");
  tx_thread_relinquish();

  return;

  /* USER CODE END Nx_App_Thread_Entry 1 */

} /* nx_app_thread_entry */


/* USER CODE BEGIN 1 */



void LedThread_Entry(ULONG thread_input)
{
  (void) thread_input;
  /* Infinite loop */
  while (1)
  {
    HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);

    /* Delay for 500ms (App_Delay is used to avoid context change). */
    tx_thread_sleep(50);
  }
}

/**
  * @brief  Link thread entry
  * @param thread_input: ULONG thread parameter
  * @retval none
  */
static VOID App_Link_Thread_Entry(ULONG thread_input)
{
  ULONG actual_status;
  UINT linkdown = 0, status;

  while(1)
  {
    /* Send request to check if the Ethernet cable is connected. */
    status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_LINK_ENABLED,
                                          &actual_status, 10);

    if(status == NX_SUCCESS)
    {
      if(linkdown == 1)
      {
        linkdown = 0;

        /* The network cable is connected. */
        printf("The network cable is connected.\r\n");

        /* Send request to enable PHY Link. */
        nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_ENABLE,
                                    &actual_status);

        /* Send request to check if an address is resolved. */
        status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_ADDRESS_RESOLVED,
                                              &actual_status, 10);
        if(status == NX_SUCCESS)
        {
          /* Stop DHCP */
          nx_dhcp_stop(&DHCPClient);

          /* Reinitialize DHCP */
          nx_dhcp_reinitialize(&DHCPClient);

          /* Start DHCP */
          nx_dhcp_start(&DHCPClient);

          /* wait until an IP address is ready */
          if(tx_semaphore_get(&DHCPSemaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
          {
            /* USER CODE BEGIN DHCPSemaphore get error */
            Error_Handler();
            /* USER CODE END DHCPSemaphore get error */
          }

          PRINT_IP_ADDRESS(IpAddress);
        }
        else
        {
          /* Set the DHCP Client's remaining lease time to 0 seconds to trigger an immediate renewal request for a DHCP address. */
          nx_dhcp_client_update_time_remaining(&DHCPClient, 0);
        }
      }
    }
    else
    {
      if(0 == linkdown)
      {
        linkdown = 1;
        /* The network cable is not connected. */
        printf("The network cable is not connected.\r\n");
        nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_DISABLE,
                                    &actual_status);
      }
    }

    tx_thread_sleep(NX_APP_CABLE_CONNECTION_CHECK_PERIOD);
  }
}
/* USER CODE END 1 */
