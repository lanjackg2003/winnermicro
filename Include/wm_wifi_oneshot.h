/**************************************************************************
 * File Name                    : wm_wifi_oneshot.h
 * Author                       : WinnerMicro
 * Version                      :
 * Date                         : 05/30/2014
 * Description                  :
 *
 * Copyright (C) 2014 Beijing Winner Micro Electronics Co., Ltd.
 * All rights reserved.
 *
 ***************************************************************************/
#ifndef WM_WIFI_ONESHOT_H
#define WM_WIFI_ONESHOT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wm_type_def.h>
#if (GCC_COMPILE==1)
#include "wm_ieee80211_gcc.h"
#else
#include <wm_ieee80211.h>
#endif
#include "wm_config.h"

/*DEBUG USE MAC FILTER START*/
#define CONFIG_ONESHOT_MAC_FILTER 0
extern int tls_filter_module_srcmac(u8 *mac);
/*DEBUG USE MAC FILTER END*/

/*一键配置下，增加联网开始的随机时间*/
#define CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT 0


/* 一键配置的工作模式，0为apsta模式, 其它为sta模式 */
#define CONFIG_NORMAL_MODE_ONESHOT 1


u8 tls_wifi_dataframe_recv(struct ieee80211_hdr *hdr, u32 data_len);

#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
#if TLS_CONFIG_SOCKET_RAW
void oneshot_airkiss_send_reply(void);
#endif
void tls_airkiss_recv(u8 *data, u16 data_len);
void tls_airkiss_start(void);
void tls_airkiss_stop(void);
#endif

#endif /*WM_WIFI_ONESHOT_H*/
