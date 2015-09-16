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
	    /* ����ʧ�� */
	    case NETIF_WIFI_JOIN_FAILED:
	        printf("apsta join net failed\n");
			break;
		/* �Ͽ����� */
		case NETIF_WIFI_DISCONNECTED:
	        printf("apsta net disconnected\n");
			break;
	    /* ���뵽ap�ɹ� */
	    case NETIF_WIFI_APSTA_STA_SUCCESS:
	        printf("apsta 1/4 sta join net success\n");
			break;
		/* ������ap�ɹ� */
        case NETIF_WIFI_APSTA_AP_SUCCESS:
            printf("apsta 2/4 ap  join net success\n");
			break;
		/* ��ap��ȡip�ɹ� */
        case NETIF_APSTA_STA_NET_UP:
            printf("apsta 3/4 sta get ip: %d.%d.%d.%d.\n", ip4_addr1(&netif->ip_addr.addr),
                                                           ip4_addr2(&netif->ip_addr.addr),
                              		                       ip4_addr3(&netif->ip_addr.addr),
                              		                       ip4_addr4(&netif->ip_addr.addr));
			break;
		/* ��ap����ip�ɹ���Ҳ�����յĳɹ��¼� */
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

//apsta����demo
//����ʾ��:t-apsta("ssid","pwd", "apsta");
int apsta_demo(char *buf)
{
    int ret = -1;
	char *p1 = NULL,*p2 = NULL;
	char ssid[64];
	char ssid2[64];
	char pwd[70];
	char *pssid2 = NULL;
	
	if(strchr(buf, ';') != NULL || strchr(buf, ')') != NULL)		//�յ������������
	{
		printf("\ninput:%s\n", buf);

		memset(ssid, 0, sizeof(ssid));
		memset(ssid2, 0, sizeof(ssid2));
		memset(pwd, 0, sizeof(pwd));

		p1 = strchr(buf, '"');
		if(NULL == p1)
			return WM_FAILED;
		p2 = p1 +1;	//ssid����ʼλ��
		p1 = strchr(p2, '"');	//ssid�Ľ���λ��
		if(NULL == p1)
			return WM_FAILED;
		MEMCPY(ssid, p2, p1 - p2);
		printf("\nssid=%s\n", ssid);

		p2 = p1 + 1;
		p1 = strchr(p2, '"');	
		if(NULL == p1)
			return WM_FAILED;
		p2 = p1 + 1;		//pwd ����ʼλ��
		p1 = strchr(p2, '"');	//pwd�Ľ���λ��
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
		p2 = p1 + 1;        //apstassid����ʼλ��
		p1 = strchr(p2, '"');//apstassid�Ľ���λ��
		if(NULL == p1)
			return WM_FAILED;
		MEMCPY(ssid2, p2, p1 - p2);
		printf("\napstassid=%s\n", ssid2);

		if (0 != strlen(ssid2))//���һ��ssid2�Ƿ�Ϊ��
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

