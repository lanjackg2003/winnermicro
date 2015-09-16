/***************************************************************************** 
* 
* File Name : wm_softap_demo.c 
* 
* Description: soft ap demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : cuiyanchang
* 
* Date : 2014-6-2 
*****************************************************************************/ 
#include <string.h>
#include "wm_include.h"

#if DEMO_SOFT_AP
int soft_ap_demo(char *buf)
{
	struct tls_softap_info_t apinfo;
	struct tls_ip_info_t ipinfo;
	u8 ret=0;
	u8 ssid_set = 0;

	u8* ssid = "soft_ap_demo";
	u8 ssid_len = strlen("soft_ap_demo");

	tls_wifi_set_oneshot_flag(0);          /*���һ�����ñ�־*/

	tls_param_get(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)0);
	if (0 == ssid_set){
		ssid_set = 1;
		tls_param_set(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)1); /*����BSSID�㲥��־*/
	}

	MEMCPY(apinfo.ssid, ssid, ssid_len);
	apinfo.ssid[ssid_len]='\0';
	
	apinfo.encrypt = 0;  /*0:open, 1:wep64, 2:wep128*/
	apinfo.channel = 11; /*channel*/
	apinfo.keyinfo.format = 1; /*�����ʽ:0��hex��ʽ��1��ascii��ʽ*/
	apinfo.keyinfo.index = 1;  /*wep����*/
	apinfo.keyinfo.key_len = strlen("1234567890123"); /*���볤��*/
	MEMCPY(apinfo.keyinfo.key, "1234567890123", strlen("1234567890123"));
	/*ip������Ϣ:ip��ַ�����룬dns����*/
	ipinfo.ip_addr[0] = 192;
	ipinfo.ip_addr[1] = 168;
	ipinfo.ip_addr[2] = 1;
	ipinfo.ip_addr[3] = 1;
	ipinfo.netmask[0] = 255;
	ipinfo.netmask[1] = 255;
	ipinfo.netmask[2] = 255;
	ipinfo.netmask[3] = 0;
	MEMCPY(ipinfo.dnsname, "local.wm", sizeof("local.wm"));
	ret = tls_wifi_softap_create((struct tls_softap_info_t* )&apinfo, (struct tls_ip_info_t* )&ipinfo);
	printf("\n ap create %s ! \n", (ret == WM_SUCCESS)? "Successfully" : "Error");

	return ret;
}

#endif
