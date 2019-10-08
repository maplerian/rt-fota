/* RT-Thread config file */

#ifndef RT_CONFIG_H__
#define RT_CONFIG_H__

#define RT_THREAD_PRIORITY_MAX  8
#define RT_TICK_PER_SECOND	1000
#define RT_ALIGN_SIZE   4
#define RT_NAME_MAX	   8

/* Kernel Device Object */

#define RT_USING_DEVICE
#define RT_USING_CONSOLE
#define RT_CONSOLEBUF_SIZE          128
#define RT_CONSOLE_DEVICE_NAME      "uart2"

#define RT_USING_CPU_FFS

/* RT-Thread Components */

#define RT_USING_COMPONENTS_INIT
#define RT_USING_USER_MAIN

#define RT_DEBUG_INIT 0
//#define RT_USING_OVERFLOW_CHECK
//#define RT_USING_HOOK
//#define RT_USING_IDLE_HOOK

/* Software timers Configuration */

#define RT_USING_TIMER_SOFT         0
#if RT_USING_TIMER_SOFT == 0
#undef RT_USING_TIMER_SOFT
#endif

#define RT_TIMER_THREAD_PRIO		4
#define RT_TIMER_THREAD_STACK_SIZE	512
#define RT_TIMER_TICK_PER_SECOND	100


/* IPC(Inter-process communication) Configuration */

#define RT_USING_SEMAPHORE
#define RT_USING_MUTEX
//#define RT_USING_EVENT
//#define RT_USING_MAILBOX
//#define RT_USING_MESSAGEQUEUE

/* Memory Management Configuration */

#define RT_USING_HEAP
//#define RT_USING_MEMPOOL
#define RT_USING_MEMHEAP
//#define RT_USING_MEMHEAP_AS_HEAP
#define RT_USING_SMALL_MEM
//#define RT_USING_TINY_SIZE

#if defined(RTE_USING_FINSH)
#define RT_USING_FINSH
#define FINSH_USING_MSH
#define FINSH_USING_MSH_ONLY
#define __FINSH_THREAD_PRIORITY     5
#define FINSH_THREAD_PRIORITY       (RT_THREAD_PRIORITY_MAX / 8 * __FINSH_THREAD_PRIORITY + 1)
#define FINSH_THREAD_STACK_SIZE     512
#define FINSH_HISTORY_LINES	        1
#define FINSH_USING_SYMTAB
#endif

/* Device Drivers */

#define RT_USING_PIN
#define RT_USING_SERIAL
//#define RT_SERIAL_USING_DMA
#define RT_USING_RTC
#define RT_USING_SPI
#define RT_USING_SFUD
#define RT_SFUD_USING_SFDP
#define RT_SFUD_USING_FLASH_INFO_TABLE
#define RT_USING_WDT

/* Utilities */

// #define RT_USING_ULOG
// #define ULOG_OUTPUT_LVL_D
// #define ULOG_OUTPUT_LVL 7
// #define ULOG_ASSERT_ENABLE
// #define ULOG_LINE_BUF_SIZE 128

/* log format */

// #define ULOG_USING_COLOR
// #define ULOG_OUTPUT_TIME
// #define ULOG_OUTPUT_LEVEL
// #define ULOG_OUTPUT_TAG
// #define ULOG_BACKEND_USING_CONSOLE

/* fal package */
#define PKG_USING_FAL
#define FAL_DEBUG_CONFIG
#define FAL_DEBUG 1
#define FAL_PART_HAS_TABLE_CFG
#define FAL_USING_SFUD_PORT
#define FAL_USING_NOR_FLASH_DEV_NAME "nor_flash0"
#define PKG_USING_FAL_LATEST_VERSION
#define PKG_FAL_VER_NUM 0x99999

/* Tinycrypt package */
#define TINY_CRYPT_AES

/* Compress package */
#define QLZ_COMPRESSION_LEVEL	3

/* Hardware Drivers Config */
#define SOC_FAMILY_STM32
#define SOC_SERIES_STM32F4
#define SOC_STM32F407VG

/* On-chip Peripheral Drivers */

#define BSP_USING_GPIO
#define BSP_USING_ON_CHIP_FLASH
#define BSP_USING_ONCHIP_RTC
#define BSP_USING_UART
#define BSP_USING_UART2
#define BSP_USING_SPI
#define BSP_USING_SPI1

/* Onboard Peripheral Drivers */

#define BSP_DATAFALSH_CS_PIN 22

/* Board extended module Drivers */

#define BSP_RS485_DIR_PIN 52



#endif
