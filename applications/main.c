/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2019-09-22     Warfalcon    first version
 */

#include <rtthread.h>

#if defined(RT_USING_FINSH) && defined(FINSH_USING_MSH)
#include <finsh.h>
#include <shell.h>
#endif

#define DBG_ENABLE
#define DBG_SECTION_NAME                    "main"

#ifdef RT_MAIN_DEBUG
#define DBG_LEVEL                           DBG_LOG
#else
#define DBG_LEVEL                           DBG_INFO
#endif

#define DBG_COLOR
#include <rtdbg.h>

const char boot_log_buf[] = 
" ____ _____      _____ ___  _____  _        \r\n\
|  _ \\_   _|	|  ___/ _ \\ _   _|/ \\      \r\n\
| |_) || |_____ | |_  || ||  | | / _ \\      \r\n\
|  _ < | |_____ |  _| ||_||  | |/ ___ \\     \r\n\
|_| \\_\\|_|	|_|   \\___/  |_/_/   \\_\\  \r\n";

void rt_fota_print_log(void)
{   
    LOG_RAW("%s", boot_log_buf);    
	LOG_RAW("2016 - 2019 Copyright by Radiation @ warfalcon \r\n");
	LOG_RAW("Version: %s build %s\r\n\r\n", RT_FOTA_SW_VERSION, __DATE__);
}

int main(void)
{    
#if defined(RT_USING_FINSH) && defined(FINSH_USING_MSH)
	finsh_set_prompt("rt-fota />");
#endif
    
    extern void rt_fota_init(void);
    rt_fota_init();

    return RT_EOK;
}

