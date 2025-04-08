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
#include "https_client.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define NX_DHCP_OPTION_ROUTER 3
// Define this if you only want to use HTTP and not HTTPS
#undef __HTTP_ONLY__
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* Ensure proper 4-byte alignment and fixed size */
ALIGN_32BYTES(UCHAR client_packet_pool_area[CLIENT_POOL_SIZE]);

ALIGN_32BYTES(static UCHAR dns_packet_pool_area[DNS_POOL_SIZE]);
/* Buffer for FileX FX_MEDIA sector cache. this should be 32-Bytes aligned to avoid
   cache maintenance issues */
ALIGN_32BYTES (uint32_t DataBuffer[512]);

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
NX_PACKET_POOL DnsPacketPool;
ULONG IpAddress;
ULONG NetMask;
ULONG free_bytes;
/* App memory pointer. */
CHAR *dynamic_pointer = NULL;      // For tx_byte_allocate

NX_WEB_HTTP_CLIENT HTTPClient;

#undef __COMPILE_SERVER__

/* Define FileX global data structures. */
/* the server reads the content from the uSD, a FX_MEDIA instance is required */
FX_MEDIA                SDMedia;


/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
static VOID nx_app_thread_entry (ULONG thread_input);  // The main application
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr); // Check for ip address change

/* USER CODE BEGIN PFP */
static VOID nx_client_thread_entry(ULONG thread_input); // the HTTP client
static VOID app_link_thread_entry(ULONG thread_input); // Check that the Ethernet link exists
static VOID led_thread_entry(ULONG thread_input); // Blink the green LED every 1/2 second
// VOID dhcp_client_callback(NX_DHCP *dhcp_client, UINT status);
VOID print_available_memory(TX_BYTE_POOL *byte_pool);
static UINT setup_dns_from_dhcp(void);
UINT configure_gateway_from_dhcp(NX_DHCP *dhcp_client, NX_IP *ip_instance);
UINT nxd_dhcp_state_get(NX_DHCP *dhcp_ptr, UINT *state);
void print_pool_state(NX_PACKET_POOL *pool, const char *label);
void check_memory_clobber (UCHAR *packet_pool_area, int pool_size, const char *label);
void print_packet_pool_structure(NX_PACKET_POOL *pool);
static UINT resolve_hostname(CHAR *host_name, ULONG *resolved_ip);

#ifdef __HTTP_ONLY__
static UINT tcp_socket_setup(NX_TCP_SOCKET *socket, ULONG resolved_ip, UINT port);
static UINT send_http_get(NX_TCP_SOCKET *socket, CHAR *host_name, CHAR *resource_path);
static UINT receive_http_response(NX_TCP_SOCKET *socket, CHAR *receive_buffer, ULONG buffer_size);
static VOID print_gateway_mac(void);
static UINT create_http_client(void);
static CHAR *find_http_body_start(CHAR *buffer);
static UINT extract_packet_to_buffer(NX_PACKET *packet, CHAR *buffer, ULONG *offset, ULONG max_size);
static ULONG parse_content_length(const CHAR *headers);
#endif


/* Init Function Prototypes */
static void log_thread_priorities(void);
static UINT create_client_packet_pool(void);
static UINT create_app_packet_pool(TX_BYTE_POOL *byte_pool);
static UINT create_ip_instance(TX_BYTE_POOL *byte_pool);
static UINT configure_ip_features(TX_BYTE_POOL *byte_pool);
static UINT create_main_thread(TX_BYTE_POOL *byte_pool);
static UINT create_auxiliary_threads(TX_BYTE_POOL *byte_pool);
static UINT create_dhcp_client(void);
static void print_thread_states(void);
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
  printf("\r\n\r\nMX_NetXDuo_Init started...\r\n");
  log_thread_priorities();
  /* USER CODE END App_NetXDuo_MEM_POOL */

  nx_system_initialize();

  /* USER CODE BEGIN 0 */
  /******************************************************************************************/
  /* NOTE: DO NOT LET  IOC regenerate this function! */
  /******************************************************************************************/

  ret = create_client_packet_pool();
  if (ret != NX_SUCCESS) return ret;

  ret = create_app_packet_pool(byte_pool);
  if (ret != NX_SUCCESS) return ret;

  ret = create_ip_instance(byte_pool);
  if (ret != NX_SUCCESS) return ret;

  ret = configure_ip_features(byte_pool);
  if (ret != NX_SUCCESS) return ret;

  ret = create_main_thread(byte_pool);
  if (ret != NX_SUCCESS) return ret;

  ret = create_auxiliary_threads(byte_pool);
  if (ret != NX_SUCCESS) return ret;

  ret = create_dhcp_client();
  if (ret != NX_SUCCESS) return ret;

  tx_semaphore_create(&DHCPSemaphore, "DHCP Semaphore", 0);

  print_available_memory(byte_pool);
  print_thread_states();

  printf("Got to the end of the MX_NetXDuo_Init function with return code = 0x%02X\r\n", ret);

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
  printf("nx_app_thread_entry setting up nx_ip_address_change_notify...\r\n");
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
  printf("nx_app_thread_entry configure start DHCP client...\r\n");
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
  printf("nx_app_thread_entry waiting until an IP address is ready...tx_semaphore_get....\r\n");
  ret = tx_semaphore_get(&DHCPSemaphore, DHCP_TIMEOUT);
  if(ret != TX_SUCCESS)
  {
    /* USER CODE BEGIN DHCPSemaphore get error */
 	printf("DHCPSemaphore get error: 0x%02X\r\n", ret);
  	Error_Handler();
    /* USER CODE END DHCPSemaphore get error */
  }

  nx_ip_address_get(&NetXDuoEthIpInstance, &IpAddress, &NetMask);
  PRINT_IP_ADDRESS(IpAddress);

  /* Setup DNS from the DHCP */
  printf("nx_app_thread_entry is going to set up DNS...\r\n");
  ret = setup_dns_from_dhcp();
  if (ret != NX_SUCCESS)
  {
	  printf("setup_dns_from_dhcp failed with error code 0x%02X\r\n", ret);
      Error_Handler();
  }
  printf("nx_app_thread_entry successfully set up DNS...\r\n");

  /* Configure the gateway correctly */
  printf("nx_app_thread_entry is going to configure the gateway...\r\n");
  ret = configure_gateway_from_dhcp(&DHCPClient, &NetXDuoEthIpInstance);
  if (ret != NX_SUCCESS)
  {
	  printf("configure_gateway_from_dhcp failed with error code 0x%02X\r\n", ret);
	  Error_Handler();
  }
  printf("nx_app_thread_entry successfully configured the gateway...\r\n");

  /* the network is correctly initialized, start the WEB client thread */
  printf("DHCP complete. Starting HTTP client thread...\r\n");
  ret = tx_thread_resume(&HttpClientThread);
  printf("HTTP client thread resuming... tx_thread_resume returned: 0x%02X\r\n", ret);


  /* this thread is not needed any more, we relinquish it */
  printf("Relinquishing nx_app_thread_entry as it is not required anymore...\r\n");
  tx_thread_relinquish();

  return;

  /* USER CODE END Nx_App_Thread_Entry 1 */

} /* nx_app_thread_entry */


/* USER CODE BEGIN 1 */
#ifdef __HTTP_ONLY__
static VOID nx_client_thread_entry(ULONG thread_input)
{
    NX_TCP_SOCKET socket;
    ULONG ip;
    CHAR *host = "httpbin.org";
    CHAR *path = "/get";
    char response[2048];

    printf("Entered nx_client_thread_entry...\r\n");

    if (resolve_hostname(host, &ip) != NX_SUCCESS) Error_Handler();
    if (create_http_client() != NX_SUCCESS) Error_Handler();
    print_gateway_mac();

    if (tcp_socket_setup(&socket, ip, NX_WEB_HTTP_PORT) != NX_SUCCESS) {
        printf("TCP connection failed.\r\n");
        Error_Handler();
    }

    if (send_http_get(&socket, host, path) != NX_SUCCESS) {
        printf("Send failed.\r\n");
        Error_Handler();
    }

    if (receive_http_response(&socket, response, sizeof(response)) != NX_SUCCESS) {
        printf("Receive failed.\r\n");
        Error_Handler();
    }

    nx_tcp_socket_disconnect(&socket, NX_IP_PERIODIC_RATE);
    nx_tcp_client_socket_unbind(&socket);
    nx_tcp_socket_delete(&socket);
    nx_web_http_client_delete(&HTTPClient);

    printf("Successfully completed HTTP Client GET send and Receive...\r\n");
    tx_thread_resume(&LedThread);

    while (1) {
        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
    }
} /* nx_client_thread_entry */
#else
static VOID nx_client_thread_entry(ULONG thread_input)
{
    printf("Entered nx_client_thread_entry...\r\n");

    ULONG ip;
#undef __USE_HTTPBIN__
#define __USE_ONE_WAY_TLS__
#if defined(__USE_HTTPBIN__)
    CHAR *host = "httpbin.org";
    CHAR *path = "/get";
#elif defined(__USE_ONE_WAY_TLS__)
    CHAR *host = "one-way-tls.keyfactoriot.com";
    CHAR *path = "/";
#else
    CHAR *host = "iot-proxy.keyfactoriot.com";
    CHAR *path = "/mtls-connect";
#endif
    CHAR response[2048];

    if (resolve_hostname(host, &ip) != NX_SUCCESS) {
        printf("DNS resolution failed.\r\n");
        Error_Handler();
    }


    if (https_client_get(host, path, NX_WEB_HTTPS_PORT, response, sizeof(response)) != 0) {
        printf("HTTPS GET request failed.\r\n");
        Error_Handler();
    } else {
        printf("HTTPS GET succeeded. Response:\r\n\r\n%s\r\n\r\n", response);
    }

    printf("HTTPS GET completed successfully.\r\n");
    tx_thread_resume(&LedThread);

    while (1) {
        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
    }
}

#endif

/**
 * @brief  Toggle the green LED every 1/2 second
 * @param thread_input: ULONG thread parameter
 * @retval none
 */
void led_thread_entry(ULONG thread_input)
{
  (void) thread_input;
  printf("Entered led_thread_entry...\r\n");
  /* Infinite loop */
  while (1)
  {
    HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);

    /* Delay for 500ms (App_Delay is used to avoid context change). */
    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND / 2);  // 500ms
  }
} /* led_thread_entry */

/**
  * @brief  Thread to make sure if the Ethernet cable is connected.
  * @param thread_input: ULONG thread parameter
  * @retval none
  */
static VOID app_link_thread_entry(ULONG thread_input)
{
  ULONG actual_status;
  UINT linkdown = 0, status, ret;

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
          ret = nx_dhcp_start(&DHCPClient);
          if (ret != NX_SUCCESS)
          {
            printf("nx_dhcp_start failed: 0x%02X\r\n", ret);
          }
          printf("DHCP Client started successfully.\r\n");

          /* wait until an IP address is ready */
          printf("Waiting until an IP address is ready before moving on...\r\n");
          if(tx_semaphore_get(&DHCPSemaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
          {
            /* USER CODE BEGIN DHCPSemaphore get error */
            Error_Handler();
            /* USER CODE END DHCPSemaphore get error */
          }
          printf("IP Address has been obtained...\r\n");
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
} /* app_link_thread_entry */

/**
 * @breif Print the available memory
 */
VOID print_available_memory(TX_BYTE_POOL *byte_pool)
{
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
} /* print_available_memory */

static UINT setup_dns_from_dhcp(void)
{
    printf("setup_dns_from_dhcp entered...\r\n");

    UINT ret;
    UCHAR dns_buffer[16];  // Only handling one IPv4 address here but allow for 4
    UINT dns_size;
    ULONG dns_server_address;
    UINT dhcp_state;
    UINT attempt = 0;
    UINT max_attempts = 20;  // 20 x 500ms = 10 seconds

    printf("Creating DNS Packet Pool with a size of ... %u\r\n", DNS_POOL_SIZE);
    ret = nx_packet_pool_create(&DnsPacketPool, "DNS Pool",
                                DNS_PACKET_SIZE,
                                dns_packet_pool_area,
                                DNS_POOL_SIZE);
    if (ret != NX_SUCCESS)
    {
        printf("DNS packet pool creation failed: 0x%02X\r\n", ret);
        Error_Handler();
    }
    printf("Successfully created DNS packet pool with a size of %u\r\n", DNS_POOL_SIZE);

    printf("Waiting for DHCP client to reach BOUND state...\r\n");

    // Wait until DHCP is bound (i.e. has completed the lease negotiation)
    while (attempt++ < max_attempts)
    {
        ret = nxd_dhcp_state_get(&DHCPClient, &dhcp_state);
        if (ret != NX_SUCCESS)
        {
            printf("nx_dhcp_state_get failed: 0x%02X\r\n", ret);
            return ret;
        }

        if (dhcp_state == NX_DHCP_STATE_BOUND)
        {
            printf("DHCP state is BOUND.\r\n");
            break;
        }

        printf("DHCP not bound yet (state: 0x%02X), waiting...\r\n", dhcp_state);
        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND / 2);  // 500ms
    }

    if (dhcp_state != NX_DHCP_STATE_BOUND)
    {
        printf("Timeout waiting for DHCP to bind.\r\n");
        return NX_DHCP_ERROR;
    }

    printf("Establishing the DNS client...\r\n");

    ret = nx_dns_create(&DnsClient, &NetXDuoEthIpInstance, (UCHAR *)"DNS Client");
    if (ret != NX_SUCCESS)
    {
        printf("nx_dns_create failed: 0x%02X\r\n", ret);
        return ret;
    }
    nx_dns_packet_pool_set(&DnsClient, &DnsPacketPool);


    attempt = 0;
    max_attempts = 5;
    while (attempt++ < max_attempts)
    {
        dns_size = sizeof(dns_buffer);
        ret = nx_dhcp_interface_user_option_retrieve(&DHCPClient,
                                                     0,
                                                     NX_DHCP_OPTION_DNS_SVR,
                                                     dns_buffer,
                                                     &dns_size);

        if (ret == NX_SUCCESS)
        {
            printf("DNS server from DHCP: %u.%u.%u.%u\r\n",
                   dns_buffer[0], dns_buffer[1], dns_buffer[2], dns_buffer[3]);

#define __HOST_ENDIAN_IP__
#ifdef __HOST_ENDIAN_IP__
            dns_server_address = (dns_buffer[3] << 24) |
                                 (dns_buffer[2] << 16) |
                                 (dns_buffer[1] << 8)  |
                                  dns_buffer[0];
#else
            dns_server_address = (dns_buffer[0] << 24) |
                                 (dns_buffer[1] << 16) |
                                 (dns_buffer[2] << 8) |
                                  dns_buffer[3];
#endif

            ret = nx_dns_server_add(&DnsClient, dns_server_address);
            if (ret != NX_SUCCESS)
            {
                printf("nx_dns_server_add failed: 0x%02X\r\n", ret);
                return ret;
            }

            return NX_SUCCESS;
        }

        printf("DNS option not ready (attempt %u), ret=0x%02X\r\n", attempt, ret);
        tx_thread_sleep(5 *TX_TIMER_TICKS_PER_SECOND ); // Wait 5 sec
    }

    printf("Failed to retrieve DNS server from DHCP after %u attempts\r\n", max_attempts);
    return ret;
} /* setup_dns_from_dhcp */

UINT nxd_dhcp_state_get(NX_DHCP *dhcp_ptr, UINT *state)
{
	printf("nxd_dhcp_state_get entered...\r\n");
    if (dhcp_ptr == NX_NULL || state == NX_NULL)
    {
        return NX_PTR_ERROR;
    }

    *state = dhcp_ptr->nx_dhcp_interface_record[0].nx_dhcp_state;
    printf("nxd_dhcp_state_get found state = 0x%02X\r\n", *state);
    return NX_SUCCESS;
} /* nxd_dhcp_state_get */

UINT configure_gateway_from_dhcp(NX_DHCP *dhcp_client, NX_IP *ip_instance)
{
    printf("configure_gateway_from_dhcp entered\r\n");
    UCHAR gateway_buffer[16];
    UINT  gateway_size = sizeof(gateway_buffer);
    UINT  ret;

    /* Wait until IP interface is resolved before setting gateway */
    ULONG actual_status;
    ret = nx_ip_interface_status_check(ip_instance, 0, NX_IP_ADDRESS_RESOLVED, &actual_status, 100);
    if (ret != NX_SUCCESS)
    {
        printf("IP interface is not ready (status: 0x%02X). Cannot set gateway.\r\n", ret);
        return ret;
    }
    printf("IP interface is ready (status: 0x%02X).\r\nCalling nx_dhcp_interface_user_option_retrieve.\r\n", ret);

    ret = nx_dhcp_interface_user_option_retrieve(dhcp_client, 0,
              NX_DHCP_OPTION_ROUTER, gateway_buffer, &gateway_size);


    if (ret == NX_SUCCESS)
    {
        ULONG gw = (gateway_buffer[3] << 24) |
                   (gateway_buffer[2] << 16) |
                   (gateway_buffer[1] << 8)  |
                    gateway_buffer[0];

        printf("Retrieved gateway address of ");
        PRINT_IP_ADDRESS(gw);
        printf("gw variable is set to 0x%lx\r\n", gw);
        printf("Attempting to call nx_ip_gateway_address_set(ip_instance, gw)\r\n");

        ret = nx_ip_gateway_address_set(ip_instance, gw);
        if (ret != NX_SUCCESS)
        {
            printf("Failed to set gateway IP, ret=0x%02X\r\n", ret);
            return ret;
        }

        printf("Gateway set to ");
        PRINT_IP_ADDRESS(gw);
    }
    else
    {
        printf("Failed to retrieve gateway from DHCP, ret=0x%02X\r\n", ret);
    }

    return ret;
} /* configure_gateway_from_dhcp */

void print_pool_state(NX_PACKET_POOL *pool, const char *label) {
    ULONG total, free, empty_requests, empty_suspensions, invalid_releases;

    /* Prototype from the header */
    /*
    UINT  _nxe_packet_pool_info_get(NX_PACKET_POOL *pool_ptr,
                                    ULONG *total_packets,
                                    ULONG *free_packets,
                                    ULONG *empty_pool_requests,
                                    ULONG *empty_pool_suspensions,
                                    ULONG *invalid_packet_releases);
    */
    /* end prototype */
    nx_packet_pool_info_get(pool,
    		                &total,             // total packets
			                &free,              // free packets
			                &empty_requests,    // empty pool requests
			                &empty_suspensions, // empty pool suspensions
			                &invalid_releases); // invalid packet releases
    printf("[%s] Packet Pool: total=%lu, free=%lu, used=%lu, empty_requests=%lu, empty_suspensions=%lu, invalid_releases=%lu\r\n",
           label, total, free, total - free, empty_requests, empty_suspensions, invalid_releases);
} /* print_pool_state */

void print_packet_pool_structure(NX_PACKET_POOL *pool) {
    printf("Packet Pool Structure:\r\n");
    printf("  nx_packet_pool_id: 0x%08lX\r\n", pool->nx_packet_pool_id);
    printf("  nx_packet_pool_name: %s\r\n", pool->nx_packet_pool_name);
    printf("  nx_packet_pool_total: %lu\r\n", pool->nx_packet_pool_total);
    printf("  nx_packet_pool_available: %lu\r\n", pool->nx_packet_pool_available);
    printf("  nx_packet_pool_start: %p\r\n", pool->nx_packet_pool_start);
    printf("  nx_packet_pool_size: %lu\r\n", pool->nx_packet_pool_size);
    printf("  nx_packet_pool_created_next: %p\r\n", pool->nx_packet_pool_created_next);
    printf("  nx_packet_pool_created_previous: %p\r\n", pool->nx_packet_pool_created_previous);
} /* print_packet_pool_structure */

static UINT resolve_hostname(CHAR *host_name, ULONG *resolved_ip)
{
	printf("Resolving via DNS the host name %s\r\n", host_name);
    UINT status = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)host_name, resolved_ip, 5 * TX_TIMER_TICKS_PER_SECOND);
    if (status != NX_SUCCESS) {
        printf("DNS resolution failed: 0x%02X\r\n", status);
        return status;
    }
    printf("DNS resolved %s to ", host_name);
    PRINT_IP_ADDRESS(*resolved_ip);
    return NX_SUCCESS;
} /* resolve_hostname */


static void log_thread_priorities(void)
{
    printf("\r\n\r\nMX_NetXDuo_Init started...\r\n");
    printf("Thread priorities are:\r\n");
    printf("\tNX_APP_THREAD_PRIORITY = %u\r\n", NX_APP_THREAD_PRIORITY);
    printf("\tDEFAULT_PRIORITY       = %u\r\n", DEFAULT_PRIORITY);
    printf("\tLINK_PRIORITY          = %u\r\n", LINK_PRIORITY);
    printf("\tTOGGLE_LED_PRIORITY    = %u\r\n", TOGGLE_LED_PRIORITY);
    printf("\tNX_APP_THREAD_STACK_SIZE = %u\r\n", NX_APP_THREAD_STACK_SIZE);
    printf("\r\n");
} /* log_thread_priorities */

static UINT create_client_packet_pool(void)
{
    printf("client_packet_pool_area @ 0x%08lX\r\n", (uint32_t)client_packet_pool_area);
    printf("client_packet_pool_area alignment: %u\r\n", (uintptr_t)client_packet_pool_area % 32);
    printf("CLIENT_POOL_SIZE: %u\r\n", CLIENT_POOL_SIZE);

    printf("Creating the HTTP client packet pool with %u bytes...\r\n", CLIENT_POOL_SIZE);
    UINT ret = nx_packet_pool_create(&ClientPacketPool, "HTTP Client Packet Pool",
                                     CLIENT_PACKET_SIZE,
                                     client_packet_pool_area,
                                     CLIENT_POOL_SIZE);
    print_packet_pool_structure(&ClientPacketPool);
    print_pool_state(&ClientPacketPool, "Client Packet Pool After pool create");

    if (ret != NX_SUCCESS)
        printf("nx_packet_pool_create failed: 0x%02X\r\n", ret);
    else
        printf("nx_packet_pool_create success\r\n");

    return ret;
} /* create_client_packet_pool */

static UINT create_app_packet_pool(TX_BYTE_POOL *byte_pool)
{
    UINT ret;
    printf("Allocating memory for the packet pool with a thread size = %u\r\n", NX_APP_PACKET_POOL_SIZE);
    print_available_memory(byte_pool);

    ret = tx_byte_allocate(byte_pool, (VOID **) &dynamic_pointer, NX_APP_PACKET_POOL_SIZE, TX_NO_WAIT);
    if (ret != TX_SUCCESS) {
        printf("tx_byte_allocate for packet pool failed: 0x%02X\r\n", ret);
        return TX_POOL_ERROR;
    }
    printf("The application packet pool was created at 0x%08lX\r\n", (uint32_t)dynamic_pointer);

    printf("Creating the NetXDuo App Pool packet pool...\r\n");
    ret = nx_packet_pool_create(&NxAppPool, "NetXDuo App Pool",
                                DEFAULT_PAYLOAD_SIZE, dynamic_pointer, NX_APP_PACKET_POOL_SIZE);
    if (ret != NX_SUCCESS)
        printf("nx_packet_pool_create for NetXDuo App packet pool failed: 0x%02X\r\n", ret);

    return ret;
} /* create_app_packet_pool */

static UINT create_ip_instance(TX_BYTE_POOL *byte_pool)
{
    UINT ret;
    printf("Allocating memory for the IP Instance with a thread size = %u\r\n", Nx_IP_INSTANCE_THREAD_SIZE);
    print_available_memory(byte_pool);
    ret = tx_byte_allocate(byte_pool, (VOID **) &dynamic_pointer, Nx_IP_INSTANCE_THREAD_SIZE, TX_NO_WAIT);
    if (ret != TX_SUCCESS) return TX_POOL_ERROR;

    printf("Creating the main NetX IP instance...\r\n");
    ret = nx_ip_create(&NetXDuoEthIpInstance, "NetX Ip instance", NX_APP_DEFAULT_IP_ADDRESS,
                       NX_APP_DEFAULT_NET_MASK, &NxAppPool, nx_stm32_eth_driver,
                       dynamic_pointer, Nx_IP_INSTANCE_THREAD_SIZE, NX_APP_INSTANCE_PRIORITY);
    if (ret != NX_SUCCESS)
        printf("nx_ip_create failed: 0x%02X\r\n", ret);
    return ret;
} /* create_ip_instance */

static UINT configure_ip_features(TX_BYTE_POOL *byte_pool)
{
    UINT ret;

    // Allocate ARP memory
    printf("Allocating memory for ARP with a thread size = %u\r\n", DEFAULT_ARP_CACHE_SIZE);
    print_available_memory(byte_pool);
    ret = tx_byte_allocate(byte_pool, (VOID **) &dynamic_pointer, DEFAULT_ARP_CACHE_SIZE, TX_NO_WAIT);
    if (ret != TX_SUCCESS) return TX_POOL_ERROR;

    printf("Enable the ARP protocol...\r\n");
    ret = nx_arp_enable(&NetXDuoEthIpInstance, (VOID *)dynamic_pointer, DEFAULT_ARP_CACHE_SIZE);
    if (ret != NX_SUCCESS) return ret;

    printf("Enabling ICMP...\r\n");
    ret = nx_icmp_enable(&NetXDuoEthIpInstance);
    if (ret != NX_SUCCESS) return ret;

    ret = nx_tcp_enable(&NetXDuoEthIpInstance);
    if (ret != NX_SUCCESS) {
        printf("nx_tcp_enable failed: 0x%02X\r\n", ret);
        return ret;
    }

    printf("Enabling UDP...\r\n");
    ret = nx_udp_enable(&NetXDuoEthIpInstance);
    if (ret != NX_SUCCESS) {
        printf("nx_udp_enable failed: 0x%02X\r\n", ret);
        return ret;
    }

    return NX_SUCCESS;
} /* configure_ip_features */

static UINT create_main_thread(TX_BYTE_POOL *byte_pool)
{
    UINT ret;

    printf("Allocating memory for the main thread with a thread size = %u\r\n", NX_APP_THREAD_STACK_SIZE);
    print_available_memory(byte_pool);
    ret = tx_byte_allocate(byte_pool, (VOID **) &dynamic_pointer, NX_APP_THREAD_STACK_SIZE, TX_NO_WAIT);
    if (ret != TX_SUCCESS) return TX_POOL_ERROR;

    printf("Creating the main NetXDuo App thread...\r\n");
    ret = tx_thread_create(&NxAppThread, "NetXDuo App thread",
                           nx_app_thread_entry, 0,
                           dynamic_pointer, NX_APP_THREAD_STACK_SIZE,
                           NX_APP_THREAD_PRIORITY, NX_APP_THREAD_PRIORITY,
                           TX_NO_TIME_SLICE, TX_AUTO_START);
    if (ret != TX_SUCCESS)
        printf("tx_thread_create for the main thread failed: 0x%02X\r\n", ret);

    return ret;
} /* create_main_thread */

static UINT create_auxiliary_threads(TX_BYTE_POOL *byte_pool)
{
    UINT ret;
    UINT state;

    // HTTP client thread
	printf("Allocating memory for HTTP client thread with a thread size = %u\r\n", WEB_CLIENT_THREAD_SIZE);
	print_available_memory(byte_pool);
	ret = tx_byte_allocate(byte_pool, (VOID **) &dynamic_pointer, WEB_CLIENT_THREAD_SIZE, TX_NO_WAIT);
    if (ret != TX_SUCCESS) {
    	printf("tx_byte_allocate failed with code 0x%X\r\n", ret);
    	Error_Handler();
    }
    printf("HTTP client thread memory allocated successfully...\r\n");

    printf("Creating the HTTP client thread...\r\n");
    ret = tx_thread_create(&HttpClientThread, "App Client Thread", nx_client_thread_entry, 0,
						   dynamic_pointer, WEB_CLIENT_THREAD_SIZE,
						   DEFAULT_PRIORITY, DEFAULT_PRIORITY,
						   TX_NO_TIME_SLICE, TX_DONT_START);
    if (ret != TX_SUCCESS) {
		printf("tx_thread_create failed with code 0x%X\r\n", ret);
		Error_Handler();
	}
    printf("HTTP client thread created successfully...\r\n");

    tx_thread_info_get(&HttpClientThread, NX_NULL, &state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    printf("HttpClientThread initial state: %u\r\n", state);

    // LED thread
    printf("Allocating memory for the Green LED thread with a thread size = %u\r\n", TOGGLE_LED_STACK_SIZE);
	print_available_memory(byte_pool);
	ret = tx_byte_allocate(byte_pool, (VOID **) &dynamic_pointer, TOGGLE_LED_STACK_SIZE, TX_NO_WAIT);
    if (ret != TX_SUCCESS) {
		printf("tx_byte_allocate failed with code 0x%X\r\n", ret);
		Error_Handler();
	}
    printf("Green LED memory allocated successfully...\r\n");

    printf("Creating the Green LED control thread...\r\n");
    ret = tx_thread_create(&LedThread, "LED control Thread", led_thread_entry, 0,
						   dynamic_pointer, TOGGLE_LED_STACK_SIZE,
						   TOGGLE_LED_PRIORITY, TOGGLE_LED_PRIORITY,
						   TX_NO_TIME_SLICE, TX_DONT_START);
    if (ret != TX_SUCCESS) {
		printf("tx_thread_create failed with code 0x%X\r\n", ret);
		Error_Handler();
	}
    printf("Green LED thread created successfully...\r\n");

    // Link status thread
    printf("Allocating memory for the Ethernet Link Check with a thread size = %u\r\n", LINK_THREAD_STACK_SIZE);
	print_available_memory(byte_pool);
	ret = tx_byte_allocate(byte_pool, (VOID **) &dynamic_pointer, LINK_THREAD_STACK_SIZE, TX_NO_WAIT);
    if (ret != TX_SUCCESS) {
		printf("tx_byte_allocate failed with code 0x%X\r\n", ret);
		Error_Handler();
	}
    printf("Ethernet Link Check memory allocated successfully...\r\n");

    printf("Creating the Ethernet Link Check thread...\r\n");
    ret = tx_thread_create(&AppLinkThread, "App Eth Link Thread", app_link_thread_entry, 0,
						   dynamic_pointer, LINK_THREAD_STACK_SIZE,
						   LINK_PRIORITY, LINK_PRIORITY,
						   TX_NO_TIME_SLICE, TX_AUTO_START);
    if (ret != TX_SUCCESS) {
		printf("tx_thread_create failed with code 0x%X\r\n", ret);
		Error_Handler();
	}
    printf("Ethernet Link Check thread created successfully...\r\n");

    return NX_SUCCESS;
} /* create_auxiliary_threads */

static UINT create_dhcp_client(void)
{
    UINT ret;
    printf("Enabling DHCP Client...\r\n");
    ret = nx_dhcp_create(&DHCPClient, &NetXDuoEthIpInstance, "DHCP Client");
    if (ret != NX_SUCCESS)
        printf("nx_dhcp_create failed: 0x%02X\r\n", ret);
    else
        printf("DHCP Client created successfully.\r\n");
    return ret;
} /* create_dhcp_client */

static void print_thread_states(void)
{
    UINT thread_state;
    tx_thread_info_get(&NxAppThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    printf("NxAppThread state: 0x%02X\r\n", thread_state);

    tx_thread_info_get(&HttpClientThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    printf("HttpClientThread state: 0x%02X\r\n", thread_state);

    tx_thread_info_get(&AppLinkThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    printf("AppLinkThread state: 0x%02X\r\n", thread_state);

    tx_thread_info_get(&LedThread, NX_NULL, &thread_state, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    printf("LedThread state: 0x%02X\r\n", thread_state);
} /* print_thread_states */


#ifdef __HTTP_ONLY__
static UINT tcp_socket_setup(NX_TCP_SOCKET *socket, ULONG resolved_ip, UINT port)
{
	printf("tcp_socket_setup entered...\r\n");
    UINT status;
    status = nx_tcp_socket_create(&NetXDuoEthIpInstance, socket, "HTTP Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, 128, 2048, NX_NULL, NX_NULL);
    if (status != NX_SUCCESS) return status;

    status = nx_tcp_client_socket_bind(socket, NX_ANY_PORT, NX_NO_WAIT);
    if (status != NX_SUCCESS) return status;

    NXD_ADDRESS addr = { .nxd_ip_version = NX_IP_VERSION_V4, .nxd_ip_address.v4 = resolved_ip };
    status = nxd_tcp_client_socket_connect(socket, &addr, port, 5 * NX_IP_PERIODIC_RATE);
    return status;
} /* tcp_socket_setup */

static UINT create_http_client(void)
{
	printf("create_http_client entered...\r\n");
    UINT status = nx_web_http_client_create(&HTTPClient, "HTTP Client", &NetXDuoEthIpInstance, &ClientPacketPool, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
        printf("HTTP client create failed: 0x%02X\r\n", status);
        return status;
    }
    return NX_SUCCESS;
} /* create_http_client */

static VOID print_gateway_mac(void)
{
    ULONG gw_ip, msw, lsw;
    if (nx_ip_gateway_address_get(&NetXDuoEthIpInstance, &gw_ip) == NX_SUCCESS &&
        nx_arp_hardware_address_find(&NetXDuoEthIpInstance, gw_ip, &msw, &lsw) == NX_SUCCESS) {
        printf("Gateway MAC: %08lX:%08lX\r\n", msw, lsw);
    } else {
        printf("Could not resolve gateway MAC.\r\n");
    }
} /* print_gateway_mac */

static UINT send_http_get(NX_TCP_SOCKET *socket, CHAR *host_name, CHAR *resource_path)
{
	printf("send_http_get entered...\r\n");
    NX_PACKET *send_packet;
    char request[1024];

    snprintf(request,
    		sizeof(request),
            "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: nxd_tcp_client/1.0.0\r\nAccept: */*\r\n\r\n",
            resource_path,
			host_name);

    UINT status = nx_packet_allocate(NetXDuoEthIpInstance.nx_ip_default_packet_pool,
                                     &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) return status;

    status = nx_packet_data_append(send_packet, request, strlen(request),
                                   NetXDuoEthIpInstance.nx_ip_default_packet_pool, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
        nx_packet_release(send_packet);
        return status;
    }

    return nx_tcp_socket_send(socket, send_packet, NX_WAIT_FOREVER);
} /* send_http_get */

static UINT receive_http_response(NX_TCP_SOCKET *socket, CHAR *receive_buffer, ULONG buffer_size)
{
	printf("receive_http_response entered...\r\n");
    NX_PACKET *packet;
    ULONG total_received = 0;
    ULONG expected_body_length = 0;
    ULONG actual_body_length = 0;
    CHAR *body_start = NULL;

    while (nx_tcp_socket_receive(socket, &packet, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
    {
        if (extract_packet_to_buffer(packet, receive_buffer, &total_received, buffer_size) != NX_SUCCESS) {
            nx_packet_release(packet);
            break;
        }

        nx_packet_release(packet);

        // Parse headers once
        if (expected_body_length == 0 && (body_start = find_http_body_start(receive_buffer)) != NULL) {
            expected_body_length = parse_content_length(receive_buffer);
            actual_body_length = total_received - (ULONG)(body_start - receive_buffer);
            if (expected_body_length)
                printf("Content-Length = %lu bytes\r\n", expected_body_length);
            else
                printf("No Content-Length header found, reading until disconnect...\r\n");
        } else if (expected_body_length > 0 && body_start != NULL) {
            actual_body_length = total_received - (ULONG)(body_start - receive_buffer);
        }

        if (expected_body_length > 0 && actual_body_length >= expected_body_length)
            break;
    }

    receive_buffer[total_received] = '\0';

    body_start = find_http_body_start(receive_buffer);
    if (body_start)
        printf("HTTP Body:\r\n%s\r\n", body_start);
    else
        printf("HTTP Body not found. Full response:\r\n%s\r\n", receive_buffer);

    return NX_SUCCESS;
} /* receive_http_response */

static ULONG parse_content_length(const CHAR *headers)
{
	printf("parse_content_length entered...\r\n");
    const CHAR *ptr = strstr(headers, "Content-Length:");
    if (!ptr) return 0;

    ptr += strlen("Content-Length:");
    while (*ptr == ' ') ptr++;

    return strtoul(ptr, NULL, 10);
} /* parse_content_length */

static CHAR *find_http_body_start(CHAR *buffer)
{
	printf("find_http_body_start entered...\r\n");
    CHAR *pos = strstr(buffer, "\r\n\r\n");
    return (pos) ? pos + 4 : NULL;
} /* find_http_body_start */

static UINT extract_packet_to_buffer(NX_PACKET *packet, CHAR *buffer, ULONG *offset, ULONG max_size)
{
	printf("extract_packet_to_buffer entered...\r\n");
    ULONG bytes;
    if (*offset >= max_size - 1)
        return NX_SIZE_ERROR;

    UINT status = nx_packet_data_extract_offset(packet, 0,
                                                buffer + *offset,
                                                max_size - *offset - 1,
                                                &bytes);
    if (status != NX_SUCCESS)
        return status;

    *offset += bytes;
    buffer[*offset] = '\0';
    return NX_SUCCESS;
} /* extract_packet_to_buffer */
#endif

/* USER CODE END 1 */
