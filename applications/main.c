/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-11-06     SummerGift   first version
 */

#include <rtthread.h>
#include <rtdevice.h>
#include <board.h>

#include <fal.h>

#define LOG_TAG                        	"app.main"
#include <app_log.h>

int main(void)
{		
	/* partition initialized */
	fal_init(); 
														
    return RT_EOK;
}

