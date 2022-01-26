#ifndef __NEW_COMMON_H__
#define __NEW_COMMON_H__


#if WINDOWS

#include <stdlib.h>
#include <stdio.h>


typedef int bool;
#define true 1
#define false 0

#define PR_NOTICE printf
typedef unsigned char u8;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

#else
#define _TUYA_DEVICE_GLOBAL

/* Includes ------------------------------------------------------------------*/
#include "uni_log.h"
#include "tuya_iot_wifi_api.h"
#include "tuya_hal_system.h"
#include "tuya_iot_com_api.h"
#include "tuya_cloud_com_defs.h"
#include "gw_intf.h"
#include "gpio_test.h"
#include "tuya_gpio.h"
#include "tuya_key.h"
#include "tuya_led.h"
#include "wlan_ui_pub.h"

#include "lwip/sockets.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"

#include "../../beken378/func/key/multi_button.h"

#undef PR_NOTICE
#define PR_NOTICE(fmt, ...) bk_printf(fmt, ##__VA_ARGS__)

#undef PR_DEBUG
#define PR_DEBUG(fmt, ...) bk_printf(fmt, ##__VA_ARGS__)


#endif

typedef unsigned char byte;


#endif


int strcat_safe(char *tg, const char *src, int tgMaxLen);


