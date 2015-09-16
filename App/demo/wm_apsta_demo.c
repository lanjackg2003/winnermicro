/***************************************************************************** 
* 
* File Name : wm_apsta_demo.c 
* 
* Description: apsta demo function 
* 
* Copyright (c) 2015 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : LiLimin
* 
* Date : 2015-3-24
*****************************************************************************/ 
#include <string.h>
#include "wm_include.h"
#include "netif.h"

#if DEMO_APSTA
extern struct netif *tls_get_netif(void);
static void apsta_net_status_changed_event(u8 status)
{
    struct netif *netif = tls_get_netif();

	switch(status)
	{
	    /* 加网失败 */
	    case NETIF_WIFI_JOIN_FAILED:
	        printf("apsta join net failed\n");
			break;
		/* 断开网络 */
		case NETIF_WIFI_DISCONNECTED:
	        printf("apsta net disconnected\n");
			break;
	    /* 加入到ap成功 */
	    case NETIF_WIFI_APSTA_STA_SUCCESS:
	        printf("apsta 1/4 sta join net success\n");
			break;
		/* 创建软ap成功 */
        case NETIF_WIFI_APSTA_AP_SUCCESS:
            printf("apsta 2/4 ap  join net success\n");
			break;
		/* 从ap获取ip成功 */
        case NETIF_APSTA_STA_NET_UP:
            printf("apsta 3/4 sta get ip: %d.%d.%d.%d.\n", ip4_addr1(&netif->ip_addr.addr),
                                                           ip4_addr2(&netif->ip_addr.addr),
                              		                       ip4_addr3(&netif->ip_addr.addr),
                              		                       ip4_addr4(&netif->ip_addr.addr));
			break;
		/* 软ap设置ip成功，也是最终的成功事件 */
		case NETIF_IP_NET_UP:
			printf("apsta 4/4 ap  get ip: %d.%d.%d.%d.\n", ip4_addr1(&netif->next->ip_addr.addr),
                                                           ip4_addr2(&netif->next->ip_addr.addr),
                                                           ip4_addr3(&netif->next->ip_addr.addr),
                                                           ip4_addr4(&netif->next->ip_addr.addr));
			printf("spsta join net successfully.\n");
			break;
		default:
			break;
	}
}

//apsta联网demo
//命令示例:t-apsta("ssid","pwd", "apsta");
int apsta_demo(char *buf)
{
    int ret = -1;
	char *p1 = NULL,*p2 = NULL;
	char ssid[64];
	char ssid2[64];
	char pwd[70];
	char *pssid2 = NULL;
	
	if(strchr(buf, ';') != NULL || strchr(buf, ')') != NULL)		//收到了命令结束符
	{
		printf("\ninput:%s\n", buf);

		memset(ssid, 0, sizeof(ssid));
		memset(ssid2, 0, sizeof(ssid2));
		memset(pwd, 0, sizeof(pwd));

		p1 = strchr(buf, '"');
		if(NULL == p1)
			return WM_FAILED;
		p2 = p1 +1;	//ssid的起始位置
		p1 = strchr(p2, '"');	//ssid的结束位置
		if(NULL == p1)
			return WM_FAILED;
		MEMCPY(ssid, p2, p1 - p2);
		printf("\nssid=%s\n", ssid);

		p2 = p1 + 1;
		p1 = strchr(p2, '"');	
		if(NULL == p1)
			return WM_FAILED;
		p2 = p1 + 1;		//pwd 的起始位置
		p1 = strchr(p2, '"');	//pwd的结束位置
		if(NULL == p1)
			return WM_FAILED;	
		if(p1 - p2 > 64)
		{
			printf("\npassword too long,error!\n");
			return WM_FAILED;	
		}
		MEMCPY(pwd, p2, p1 - p2);
		printf("\npassword=%s\n", pwd);

		p2 = p1 + 1;
		p1 = strchr(p2, '"');	
		if(NULL == p1)
			return WM_FAILED;
		p2 = p1 + 1;        //apstassid的起始位置
		p1 = strchr(p2, '"');//apstassid的结束位置
		if(NULL == p1)
			return WM_FAILED;
		MEMCPY(ssid2, p2, p1 - p2);
		printf("\napstassid=%s\n", ssid2);

		if (0 != strlen(ssid2))//检查一下ssid2是否为空
		    pssid2 = ssid2;

		tls_netif_add_status_event(apsta_net_status_changed_event);
		ret = tls_wifi_apsta_start((u8 *)ssid, strlen(ssid), (u8 *)pwd, strlen(pwd), (u8 *)pssid2, strlen(ssid2));
        if (WM_SUCCESS == ret)
		    printf("\nplease wait connect net......\n");
		else
		    printf("\napsta connect net failed, please check configure......\n");
	}
	else
	{
		ret = DEMO_CONSOLE_SHORT_CMD;
    }

	return ret;
}
#endif

