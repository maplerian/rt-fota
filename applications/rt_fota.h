/*
 * File      : rt_fota.h
 * COPYRIGHT (C) 2012-2018, Shanghai Real-Thread Technology Co., Ltd
 *
 * Change Logs:
 * Date           Author       Notes
 * 2019-09-22     warfalcon    the first version
 */

#ifndef _RT_FOTA_H_
#define _RT_FOTA_H_

#include <stdint.h>
#include <stdio.h>
#include <rtthread.h>
#include <rtdevice.h>
#include <board.h>
#include <fal.h>
#include <tinycrypt.h>
#include <fastlz.h>
#include <quicklz.h>

#define RT_FOTA_SW_VERSION             "0.1.0"

/* OTA download partition name */
#ifndef RT_FOTA_FM_PART_NAME
#define RT_FOTA_FM_PART_NAME           "fm_area"
#endif

/* OTA default partition name */
#ifndef RT_FOTA_DF_PART_NAME
#define RT_FOTA_DF_PART_NAME           "df_area"
#endif

#if RT_FOTA_DEBUG
#ifdef assert
#undef assert
#endif
#define assert(EXPR)                                                           \
if (!(EXPR))                                                                   \
{                                                                              \
    rt_kprintf("(%s) has assert failed at %s.\n", #EXPR, __FUNCTION__);            \
    while (1);                                                                 \
}

/* debug level log */
#ifdef  log_d
#undef  log_d
#endif
#define log_d(...)                     rt_kprintf("[D/FOTA] (%s:%d) ", __FUNCTION__, __LINE__);           rt_kprintf(__VA_ARGS__);rt_kprintf("\n")

#else

#ifdef assert
#undef assert
#endif
#define assert(EXPR)                   ((void)0);

/* debug level log */
#ifdef  log_d
#undef  log_d
#endif
#define log_d(...)
#endif /* RT_OTA_DEBUG */

/* error level log */
#ifdef  log_e
#undef  log_e
#endif
#define log_e(...)                     rt_kprintf("\033[31;22m[E/FOTA] (%s:%d) ", __FUNCTION__, __LINE__);rt_kprintf(__VA_ARGS__);rt_kprintf("\033[0m\n")

/* info level log */
#ifdef  log_i
#undef  log_i
#endif
#define log_i(...)                     rt_kprintf("\033[36;22m[I/FOTA] ");                                rt_kprintf(__VA_ARGS__);rt_kprintf("\033[0m\n")

#ifdef __CC_ARM                         /* ARM Compiler */
    #define RT_FOTA_WEAK                __weak
#elif defined (__IAR_SYSTEMS_ICC__)     /* for IAR Compiler */
    #define RT_FOTA_WEAK                __weak
#elif defined (__GNUC__)                /* GNU GCC Compiler */
    #define RT_FOTA_WEAK                __attribute__((weak))
#endif /* __CC_ARM */

/**
 * AES256 encryption algorithm option
 */
#define RT_FOTA_TINY_AES_IV  	"0123456789ABCDEF"
#define RT_FOTA_TINY_AES_KEY 	"0123456789ABCDEF0123456789ABCDEF"


/**
 * FOTA firmware encryption algorithm and compression algorithm
 */
enum rt_fota_algo
{
    RT_FOTA_CRYPT_ALGO_NONE    = 0x0L,               /**< no encryption algorithm and no compression algorithm */
    RT_FOTA_CRYPT_ALGO_XOR     = 0x1L,               /**< XOR encryption */
    RT_FOTA_CRYPT_ALGO_AES256  = 0x2L,               /**< AES256 encryption */
    RT_FOTA_CMPRS_ALGO_GZIP    = 0x1L << 8,          /**< Gzip: zh.wikipedia.org/wiki/Gzip */
    RT_FOTA_CMPRS_ALGO_QUICKLZ = 0x2L << 8,          /**< QuickLZ: www.quicklz.com */
    RT_FOTA_CMPRS_ALGO_FASTLZ  = 0x3L << 8,          /**< FastLZ: fastlz.org/ */

    RT_FOTA_CRYPT_STAT_MASK    = 0xFL,
    RT_FOTA_CMPRS_STAT_MASK    = 0xFL << 8,
};
typedef enum rt_fota_algo rt_fota_algo_t;

/* FOTA error code */
typedef enum {
    RT_FOTA_NO_ERR             =  0,
    RT_FOTA_GENERAL_ERR        = -1,    /* general error */
    RT_FOTA_CHECK_FAILED       = -2,    /* check failed */
    RT_FOTA_ALGO_NOT_SUPPORTED = -3,    /* firmware algorithm not supported */
    RT_FOTA_COPY_FAILED        = -4,    /* copy firmware to destination partition failed */
    RT_FOTA_FW_VERIFY_FAILED   = -5,    /* firmware verify failed */
    RT_FOTA_NO_MEM_ERR         = -6,    /* no memory */
    RT_FOTA_PART_READ_ERR      = -7,    /* partition read error */
    RT_FOTA_PART_WRITE_ERR     = -8,    /* partition write error */
    RT_FOTA_PART_ERASE_ERR     = -9,    /* partition erase error */
} rt_fota_err_t;

#endif /* _RT_FOTA_H_ */

