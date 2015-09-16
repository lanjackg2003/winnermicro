/**************************************************************************
 * File Name                    : wm_wifi_oneshot.c
 * Author                       : WinnerMicro
 * Version                      :
 * Date                         : 05/30/2014
 * Description                  : Wifi one shot sample(UDP, PROBEREUEST)
 *
 * Copyright (C) 2014 Beijing Winner Micro Electronics Co.,Ltd.
 * All rights reserved.
 *
 ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wm_include.h"
#include "wm_mem.h"
#include "wm_type_def.h"
#if (GCC_COMPILE == 1)
#include "wm_ieee80211_gcc.h"
#else
#include "wm_ieee80211.h"
#endif
#include "wm_wifi.h"
#include "wm_wifi_oneshot.h"
#include "utils.h"
#include "wm_params.h"
#include "wm_osal.h"
#include "tls_wireless.h"


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

static u8 guconeshotflag = 0;

/*联网必须的信息*/
static u8 gucssidokflag = 0;
static u8 gucssidData[33] = {0};

static u8 gucbssidData[ETH_ALEN] = {0};
static u8 gucbssidokflag = 0;

static u8 gucpwdokflag = 0;
static u8 gucpwdData[65] ={0};

static u8 gucCustomData[3][65] ={'\0'};

#if TLS_CONFIG_UDP_ONE_SHOT
#if TLS_CONFIG_AP_MODE_ONESHOT
#define TLS_ONESHOT_SWITCHCHANTIM_CFG 0
#else
#define TLS_ONESHOT_SWITCHCHANTIM_CFG 1
#endif
#if TLS_ONESHOT_SWITCHCHANTIM_CFG
#define TLS_ONESHOT_SWITCH_TIMER_MAX 40
static tls_os_timer_t *gWifiSwitchChanTim = NULL;
#endif

static u8 gSrcMac[ETH_ALEN] = {0,0,0,0,0,0};

#define HANDSHAKE_CNT 5
u8 guchandshakeflag = 0;

u16 usIsDataIn = 0x0;
u8 airwifichan[13]={0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF};
u8 uctotalchannum = 0;

static volatile u8 gchancfm = 0xFF;

#if TLS_CONFIG_UDP_JD_ONESHOT
#define JD_VALID_DATA_OFFSET 8
#define TLS_UDP_JD_DATA_LEN 97
static u32 uljddatavalid[8] ={0,0,0,0,0,0,0,0};
static u8 *aujddata = NULL;
static u8 aujdDataLen[2] = {0xFF, 0xFF};/*SSID, PWD*/
static u8 ucjdataencodeMode = 0xFF;
static u8 jdhandshakecnt;
static u8 ucjdsyncode = 0x00;
#endif

#if TLS_CONFIG_UDP_LSD_ONESHOT
static u32 ullsddatavalid[8] ={0,0,0,0,0,0,0,0};
static u8 *aulsddata = NULL;
static u8 lsdhandshakecnt;
static u8 uclsddatalen = 0xFF;
static u8 uclsdsyncode = 0x64;
#endif
#endif

#if TLS_CONFIG_AP_MODE_ONESHOT
static u8 gucRawValid = 0;
static u8 *gaucRawData = NULL;

#define APSKT_MAX_ONESHOT_NUM (8)
#define APSKT_SSID_MAX_LEN (32)
#define ONESHOT_AP_NAME "softap"
#define SOCKET_SERVER_PORT 65532
#define SOCKET_RX_DATA_BUFF_LEN 255
#define AP_SOCK_S_MSG_SOCKET_RECEIVE_DATA 1
#define AP_SOCK_S_MSG_SOCKET_CREATE 2
#define AP_SOCK_S_MSG_WJOIN_FAILD 3

#define    AP_SOCK_S_TASK_SIZE      512
#define AP_SOCK_S_QUEUE_SIZE 32
#define AP_SOCKET_S_TASK_PRIO (TLS_WL_TASK_PRIO_MAX + 16)
tls_os_queue_t *ap_sock_s_q = NULL;
void *ap_sock_s_queue = NULL;
static OS_STK *ApSockSTaskStk = NULL;
struct tls_socket_desc *skt_descp = NULL;
typedef struct sock_recive{
    int socket_num;
	char *sock_rx_data;
	u8 sock_data_len;
}ST_Sock_Recive;
ST_Sock_Recive *sock_rx = NULL;
#endif

extern int tls_wifi_decode_new_oneshot_data(const u8 *encodeStr, u8 *outKey, u8 *outBssid, u8 *outSsid, u8 *outCustData);

static __inline int tls_is_zero_ether_addr(const u8 *a)
{
	return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]);
}

void tls_wifi_get_customdata(u8 *data){
	if (data && (gucCustomData[0][0] != '\0')){
		strcpy((char *)data, (char *)gucCustomData[0]);
	}
}
#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
extern int random_get_bytes(void *buf, size_t len);
extern int tls_get_mac_addr(u8 *mac);
u16 tls_oneshot_get_random_by_mac(void){
	u8 timeout = 50;
	u16 timeout1 = 50; 
	u8 i = 0;
	u8 LoopCnt = 0;
	u8 mac_addr[6]={0,0,0,0,0,0};
	
   	tls_get_mac_addr(mac_addr);
	if (0 == mac_addr[5]){
		LoopCnt = 10;
	}else{
		LoopCnt = mac_addr[5];
	}

	for (i =0; i < LoopCnt; i++){
		if(random_get_bytes(&timeout, 1) == 0)
		{
			if (timeout < 10){
				timeout = 25;
			}
		}
	}

	timeout1 = timeout*2;

	return timeout1;
}
#endif

#if TLS_CONFIG_AP_MODE_ONESHOT
struct tls_param_ip *ip_param_save = NULL;
u8 ip_save_flag = 0;
void tls_oneshot_save_ip_param(void)
{
	if (ip_save_flag == 0){
		struct tls_param_ip ip_param;
		tls_param_get(TLS_PARAM_ID_IP, &ip_param, TRUE);
		if (NULL == ip_param_save){
			ip_param_save = tls_mem_alloc(sizeof(struct tls_param_ip));
		}
		if (ip_param_save){
			MEMCPY(ip_param_save, &ip_param, sizeof(struct tls_param_ip));
			ip_save_flag = 1;
		}
	}
}
void tls_oneshot_restore_ip_param(void)
{
	struct tls_param_ip ip_param;

	if (ip_save_flag == 1){
		if (ip_param_save){
			MEMCPY(&ip_param, ip_param_save, sizeof(struct tls_param_ip));
			tls_param_set(TLS_PARAM_ID_IP, &ip_param, TRUE);
			tls_mem_free(ip_param_save);
			ip_param_save = NULL;
			ip_save_flag = 0;			
		}
	}
}

#endif
void tls_wifi_wait_disconnect(void)
{
//#if !CONFIG_UDP_ONE_SHOT
	struct tls_ethif *netif = NULL;

	netif = tls_netif_get_ethif();
	if (netif && (1 == netif->status)){
		tls_wifi_disconnect();
	}

	for(;;){
		netif = tls_netif_get_ethif();
		if (netif && (0 == netif->status)){
			tls_os_time_delay(50);
			break;
		}
		tls_os_time_delay(10);
	}
	//tls_os_time_delay(210);
//#endif
}

u8 tls_wifi_oneshot_connect_by_ssid_bssid(u8 *ssid, u8 *bssid, u8 *pwd)
{
//	struct tls_param_ip ip_param;

#if TLS_CONFIG_AP_MODE_ONESHOT
	tls_wifi_wait_disconnect();
	tls_oneshot_restore_ip_param();
#endif
	tls_wifi_set_oneshot_flag(0);
#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
	tls_os_time_delay(tls_oneshot_get_random_by_mac());
#endif
#if 0 /*DHCP根据当前参数配置结果来使用，默认DHCP使能*/
	tls_param_get(TLS_PARAM_ID_IP, &ip_param, FALSE);
	ip_param.dhcp_enable = true;
	tls_param_set(TLS_PARAM_ID_IP, &ip_param, FALSE);
#endif	
#if CONFIG_NORMAL_MODE_ONESHOT
	return tls_wifi_connect_by_ssid_bssid(ssid, strlen((char *)ssid), bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd));
#else
#if TLS_CONFIG_APSTA
	{
	    int ssid4ap_len = 0;
	    u8 mac_addr[ETH_ALEN];
	    u8 ssid4ap[33];

	    ssid4ap[0] = '\0';
	    memset(mac_addr, 0, ETH_ALEN);
	    tls_get_mac_addr(mac_addr);
	    ssid4ap_len = sprintf((char *)ssid4ap, "apsta_softap_%02hhX%02hhX", mac_addr[ETH_ALEN - 2], mac_addr[ETH_ALEN - 1]);
	    return tls_wifi_apsta_start_by_ssid_bssid(ssid, strlen((char *)ssid),bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd), ssid4ap, ssid4ap_len);
	}
#else
	return tls_wifi_connect_by_ssid_bssid(ssid, strlen((char *)ssid), bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd));
#endif
#endif
}
u8 tls_wifi_oneshot_connect_by_bssid(u8 *bssid, u8 *pwd)
{
//	struct tls_param_ip ip_param;
#if TLS_CONFIG_AP_MODE_ONESHOT
	tls_wifi_wait_disconnect();
	tls_oneshot_restore_ip_param();
#endif
	tls_wifi_set_oneshot_flag(0);
#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
	tls_os_time_delay(tls_oneshot_get_random_by_mac());
#endif
#if 0 /*DHCP根据当前参数配置结果来使用，默认DHCP使能*/
	tls_param_get(TLS_PARAM_ID_IP, &ip_param, FALSE);
	ip_param.dhcp_enable = true;
	tls_param_set(TLS_PARAM_ID_IP, &ip_param, FALSE);
#endif
#if CONFIG_NORMAL_MODE_ONESHOT
	return tls_wifi_connect_by_bssid(bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd));
#else
#if TLS_CONFIG_APSTA
    int ssid4ap_len = 0;
    u8 mac_addr[ETH_ALEN];
    u8 ssid4ap[33];

    ssid4ap[0] = '\0';
    memset(mac_addr, 0, ETH_ALEN);
    tls_get_mac_addr(mac_addr);
    ssid4ap_len = sprintf((char *)ssid4ap, "apsta_softap_%02hhX%02hhX", mac_addr[ETH_ALEN - 2], mac_addr[ETH_ALEN - 1]);
    return tls_wifi_apsta_start_by_bssid(bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd), ssid4ap, ssid4ap_len);
#else
    return tls_wifi_connect_by_bssid(bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd));
#endif
#endif
}

u8 tls_wifi_oneshot_connect(u8 *ssid, u8 *pwd)
{
//	struct tls_param_ip ip_param;
#if TLS_CONFIG_AP_MODE_ONESHOT
	tls_wifi_wait_disconnect();
	tls_oneshot_restore_ip_param();
#endif
	tls_wifi_set_oneshot_flag(0);
#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
	tls_os_time_delay(tls_oneshot_get_random_by_mac());
#endif
#if 0 /*DHCP根据当前参数配置结果来使用，默认DHCP使能*/
	tls_param_get(TLS_PARAM_ID_IP, &ip_param, FALSE);
	ip_param.dhcp_enable = true;
	tls_param_set(TLS_PARAM_ID_IP, &ip_param, FALSE);
#endif
#if CONFIG_NORMAL_MODE_ONESHOT
	return tls_wifi_connect(ssid, strlen((char *)ssid), pwd, (pwd==NULL) ? 0 : strlen((char *)pwd));
#else
#if TLS_CONFIG_APSTA
    int ssid4ap_len = 0;
    u8 mac_addr[ETH_ALEN];
    u8 ssid4ap[33];

    ssid4ap[0] = '\0';
    memset(mac_addr, 0, ETH_ALEN);
    tls_get_mac_addr(mac_addr);
    ssid4ap_len = sprintf((char *)ssid4ap, "apsta_softap_%02hhX%02hhX", mac_addr[ETH_ALEN - 2], mac_addr[ETH_ALEN - 1]);
    return tls_wifi_apsta_start(ssid, strlen((char *)ssid), pwd, (pwd==NULL) ? 0 : strlen((char *)pwd), ssid4ap, ssid4ap_len);
#else
    return tls_wifi_connect(ssid, strlen((char *)ssid), pwd, (pwd==NULL) ? 0 : strlen((char *)pwd));
#endif
#endif
}


#if TLS_CONFIG_AP_MODE_ONESHOT
void tls_wifi_send_oneshotinfo(const u8 * ssid,u8 len, u32 send_cnt)
{
	int i = 0;
	int j = 0;
	u8 lenNum =0;
	u8 lenremain = 0;
	if (gaucRawData == NULL){
		gaucRawData = tls_mem_alloc(len+1);
	}

	if (gaucRawData){
		memcpy(gaucRawData, ssid, len);
		lenNum = len/APSKT_SSID_MAX_LEN;
		lenremain = len%APSKT_SSID_MAX_LEN;
		for (j = 0; j< send_cnt; j++){
			for (i = 0; i < lenNum; i++){
				tls_wifi_send_oneshotdata(NULL, (const u8 *)(&(gaucRawData[i*APSKT_SSID_MAX_LEN])), APSKT_SSID_MAX_LEN);
				tls_os_time_delay(10);
			}
			if (lenremain){
				tls_wifi_send_oneshotdata(NULL, (const u8 *)(&(gaucRawData[i*APSKT_SSID_MAX_LEN])), lenremain);
				tls_os_time_delay(10);
			}
		}
		tls_mem_free(gaucRawData);
		gaucRawData = NULL;
	}
}
#endif

u8 tls_wifi_decrypt_data(u8 *data){
	u16 datatype;
	u32 tagid = 0;
	u16 typelen[6]={0,0,0,0,0,0};
	volatile u16 rawlen = 0;
    u16 hdrlen = sizeof(struct ieee80211_hdr);
	int i = 0;
	int tmpLen = 0;
	u8 ret = 0;
	//u8 ucChanId = 0;


	//ucChanId = *(u16*)(data+hdrlen+4);/*Channel ID*/
	tagid = *(u16*)(data+hdrlen+6);/*TAG*/
	if (0xA55A == tagid){
		datatype = *(u16 *)(data+hdrlen+8); /*DataType*/
		tmpLen = hdrlen + 10;
		for (i = 0; i < 6; i++){
			if ((datatype>>i)&0x1){
				typelen[i] = *((u16*)(data+tmpLen));
				tmpLen += 2;
			}
			//printf("type[%x],lenNum[%d]:%d\n",datatype, i, typelen[i]);			
		}
		rawlen = *((u16 *)(data+tmpLen));
		tmpLen += 2;
		//printf("tmpLen:%d\n", tmpLen);
		for (i = 0; i < 6; i++){
			if ((datatype>>i)&0x1){
				if (i == 0){ /*PWD*/
					strncpy((char *)gucpwdData,(char *)(data+tmpLen), typelen[i]);
					//printf("PWD:%s\n", gucpwdData);
					gucpwdokflag = 1;
					ret = 1;
				}else if (i == 1){/*BSSID*/
					memcpy((char *)gucbssidData,(char *)(data+tmpLen), typelen[i]);
					//printf("gucbssidData:%x:%x:%x:%x:%x:%x\n", gucbssidData[0], gucbssidData[1], gucbssidData[2], gucbssidData[3], gucbssidData[4], gucbssidData[5]);
					gucbssidokflag = 1;
					ret = 1;
				}else if (i == 2){/*SSID*/
					memcpy((char *)gucssidData,(char *)(data+tmpLen), typelen[i]);
					gucssidokflag = 1;
					ret = 1;
				}else{/*3-5 USER DEF*/
					memcpy((char *)gucCustomData[i - 3], (char *)(data+tmpLen), typelen[i]);
					gucCustomData[i - 3][typelen[i]] = '\0';
					ret = 0;
				}
				tmpLen += typelen[i];
			}
		}
#if TLS_CONFIG_AP_MODE_ONESHOT
		if (ret && rawlen&&(gucRawValid==0)){
			gucRawValid = 1;
			tls_wifi_send_oneshotinfo((const u8 *)(data+tmpLen), rawlen, APSKT_MAX_ONESHOT_NUM);
		}
#endif		
	}
	return ret;
}


#if TLS_CONFIG_UDP_ONE_SHOT

void tls_wifi_clear_oneshot_data(void){
#if TLS_CONFIG_UDP_JD_ONESHOT
	jdhandshakecnt = 0;
	memset(uljddatavalid, 0, 8);
	memset(aujdDataLen, 0xFF, 2);
	if(aujddata){
		memset(aujddata, 0, 128);
	}
	ucjdataencodeMode = 0xFF;
#endif

#if TLS_CONFIG_UDP_LSD_ONESHOT
	lsdhandshakecnt = 0;
	memset(ullsddatavalid, 0, 8);
	if (aulsddata){
		memset(aulsddata, 0, 256);
	}
	uclsddatalen = 0xFF;
#endif

}

static __inline u8 tls_compare_ether_addr(const u8 *addr1, const u8 *addr2)
{
	return !((addr1[0] == addr2[0]) && (addr1[1] == addr2[1]) && (addr1[2] == addr2[2]) &&   \
		(addr1[3] == addr2[3]) && (addr1[4] == addr2[4]) && (addr1[5] == addr2[5]));
}

static __inline u8 tls_wifi_compare_mac_addr(u8 *macaddr){
	u8 tmpmacaddr[ETH_ALEN] = {0, 0,0,0,0,0};	

	if (macaddr == NULL){
		return 0;
	}

	if (tls_compare_ether_addr(gSrcMac, tmpmacaddr) == 0){
		MEMCPY(gSrcMac, macaddr, ETH_ALEN);
		return 0;
	}

	if (tls_compare_ether_addr(gSrcMac, macaddr) == 0){
		return 1;
	}
	return 0;
}
#if TLS_ONESHOT_SWITCHCHANTIM_CFG
extern u16 tls_wifi_get_oneshot_chan(void);
void tls_wifi_switch_channel_tim(void *ptmr, void *parg){
	static u8 chanid = 0;
	static u8 nextchanid = 0;
	//static u8 fixedch = 0xFF;
	static u8 ucTstFlag = 0;
	u8 chanarray[13] = {0,5,10,1,6,11,2,7,12,3,8,4,9};
	static u16 lastchaninfo = 0;
	static u16 validflag = 0;
	static u16 chanround = 0;

	if (tls_wifi_get_oneshot_flag()== 1){
#if 0	
		if (tls_wifi_get_oneshot_chan() < 14){
			if (0xFF == fixedch){
				memset(gSrcMac, 0, ETH_ALEN);
				tls_wifi_clear_oneshot_data();
				fixedch = tls_wifi_get_oneshot_chan();
				tls_wifi_change_chanel(fixedch);
			}
		}else
#endif		
		{ /*UDP confirm chan*/
			if (0 == guchandshakeflag){
				ucTstFlag = 0;
				if(validflag){
					++nextchanid;
					if (nextchanid%2){
						chanid = (nextchanid/2)%uctotalchannum;
					}else{
						chanid = (nextchanid/2+uctotalchannum/2)%uctotalchannum;
					}
//					printf("chanid:%d, uctotalchannum:%d\n", airwifichan[chanid], uctotalchannum);
				}else{
					chanid = (++nextchanid)%13;
				}
				if (chanid == 0){
					memset(gSrcMac, 0, ETH_ALEN);
					tls_wifi_clear_oneshot_data();
				}

				if ((nextchanid>13)&&(airwifichan[chanid] != 0xF)){
					tls_wifi_change_chanel(airwifichan[chanid]);
					
					if ((0 == validflag)&&(lastchaninfo != 0)&&(lastchaninfo == usIsDataIn)){
						validflag = 1;
					}
					lastchaninfo = usIsDataIn;
					if (validflag){
						chanround++;
						if (chanround > (2*uctotalchannum)){
							validflag = 0;
							nextchanid = 0;
							chanround = 0;
						}
					}
				}
				else
				{
					tls_wifi_change_chanel(chanarray[chanid]);
				}
			}else{
	 			if (0xFF == gchancfm){
					if (validflag){
						++nextchanid;
						if (nextchanid%2){
							chanid = (nextchanid/2)%uctotalchannum;
						}else{
							chanid = (nextchanid/2+uctotalchannum/2)%uctotalchannum;
						}
						if (airwifichan[chanid] != 0xF){
							//printf("chanid:%d\n", chanid);
							tls_wifi_change_chanel(airwifichan[chanid]);
						}
					}else{
						chanid = (++nextchanid)%13;
						tls_wifi_change_chanel(chanarray[chanid]);
					}
				}else{
					if (0 == ucTstFlag){
						ucTstFlag = 1;
						//printf("gchancfm:%d\n", gchancfm);
						tls_wifi_change_chanel(gchancfm);
					}
				}				
			}
		}
	}
	tls_os_timer_change(gWifiSwitchChanTim, TLS_ONESHOT_SWITCH_TIMER_MAX);	
}
#endif
#if TLS_CONFIG_UDP_JD_ONESHOT
void tls_wifi_jd_set_syncode(u8 syncode){
	ucjdsyncode = syncode;
}
int tls_wifi_jd_check_condition(u8 *addr){
	/*multicast ip Addr range:239.118~239.121*/
	if ((0x01 != addr[0])||(0x00 != addr[1])||(0x5e != addr[2])){
		return -1;
	}

	if ((addr[3]<0x76)||(addr[3]>0x7A)){ 
		return -1;
	}
	if ((addr[4] == 0) || (addr[4] > (TLS_UDP_JD_DATA_LEN+6))){
		return -1;
	}
	return 0;
}

int tls_wifi_jd_oneshot(struct ieee80211_hdr *hdr){
	u8 *SrcMacAddr = NULL;
	u8 *DstMacAddr = NULL;
	u8 index = 0;
	u8 jdIndex = 0;
	u8 jdData = 0;
	u8 i = 0;
	u8 j = 0;
	u8 *BssidMacAddr = NULL;

	DstMacAddr = ieee80211_get_DA(hdr);
	if (tls_wifi_jd_check_condition(DstMacAddr)<0){
		return 1;
	}

	SrcMacAddr = ieee80211_get_SA(hdr);
#if CONFIG_ONESHOT_MAC_FILTER	
	if (0 == tls_filter_module_srcmac(SrcMacAddr)){
		return -1;
	}
#endif
	if (NULL == aujddata){
		return -1;
	}

	if (tls_wifi_compare_mac_addr(SrcMacAddr)){
		jdIndex = DstMacAddr[4];
		jdData	= DstMacAddr[5];
		if (jdIndex >= JD_VALID_DATA_OFFSET){		/*Save Data*/
			index = jdIndex - JD_VALID_DATA_OFFSET;
			if (0 == ((uljddatavalid[index/32]>>(index%32))&0x1)){
				aujddata[index] = jdData;
				uljddatavalid[index/32] |= 1 << (index%32);
			}
		}

		if ((jdIndex < 5)&&(ucjdataencodeMode == 0xFF)){
			if (ucjdsyncode == jdData){
				ucjdataencodeMode = jdData;
			}
		}

		for (i = 0; i < 2; i++){
			if ((jdIndex == (i+6))&&((aujdDataLen[i] == 0xFF)||(aujdDataLen[i] != jdData))){
				if ((aujdDataLen[i] != 0xFF) && (aujdDataLen[i] != jdData)){
					for (j = 0; j < aujdDataLen[i]; j++){
						if (uljddatavalid[j/32]>>(j%32)&0x01){
							aujddata[j] = 0;
							uljddatavalid[j/32] &= ~(1<<(j%32));
						}
					}
				}

				if ((i==0)&&(jdData <= 32)){
					aujdDataLen[i] = jdData; /*SSID LEN*/
				}else if ((i == 1)&&(jdData <= 64)){
					aujdDataLen[i] = jdData; /*PWD LEN*/
				}
			}
		}
	}
	else{
		return -1;
	}
	if (0 == guchandshakeflag){ /*sync*/
		if ((DstMacAddr[4]<5)&&(ucjdsyncode == DstMacAddr[5])){
			++jdhandshakecnt;
		}
		if (jdhandshakecnt >= HANDSHAKE_CNT){
			guchandshakeflag = 1;
			if (ieee80211_has_tods(hdr->frame_control)){
				BssidMacAddr = hdr->addr1;
			}else if (ieee80211_has_fromds(hdr->frame_control)){
				BssidMacAddr = hdr->addr2;
			}
			if (BssidMacAddr){
				memcpy(gucbssidData, BssidMacAddr, ETH_ALEN);
			}
			printf("[JD:%d]gSrcMac:%x:%x:%x:%x:%x:%x\n",tls_os_get_time(), gSrcMac[0], gSrcMac[1], gSrcMac[2], gSrcMac[3], gSrcMac[4], gSrcMac[5]);
		}
	}else{	/*data handle*/
		if ((aujdDataLen[0] != 0xFF)&&(aujdDataLen[1] != 0xFF)){
			for (i = 0; i < (aujdDataLen[0] + aujdDataLen[1]); i++){
				if ((uljddatavalid[i/32]>>(i%32))&0x1){
					continue;
				}
				break;
			}

			if (i == (aujdDataLen[0] + aujdDataLen[1])){
				if (ucjdataencodeMode == ucjdsyncode){
					aujddata[aujdDataLen[0] + aujdDataLen[1]] = '\0';
					memcpy(gucssidData, aujddata, aujdDataLen[0]);
					gucssidData[aujdDataLen[0]] = '\0';
					memcpy(gucpwdData, &aujddata[aujdDataLen[0]], aujdDataLen[1]);
					gucpwdData[aujdDataLen[1]] = '\0';
					printf("[JDONESHOT]recv ok:%d\n", tls_os_get_time());
					printf("[JDONESHOT]SSID:%s\n", gucssidData);		
					printf("[JDONESHOT]PASSWORD:%s\n", gucpwdData);
					tls_wifi_oneshot_connect(gucssidData, gucpwdData);
				}else{
					tls_wifi_clear_oneshot_data();
					guchandshakeflag = 0;
					gchancfm = 0xFF;
				}
				return 0;
			}
		}
	}
	return -1;
}
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT
void tls_wifi_lsd_set_syncode(u8 syncode){
	uclsdsyncode = syncode;
}
int tls_wifi_lsd_oneshot(struct ieee80211_hdr *hdr){
	u8 *SrcMacAddr = NULL;
	u8 *DstMacAddr = NULL;
	u8 index = 0;
	u8 lsdIndex = 0;
	u8 lsdData1 = 0;
	u8 lsdData = 0;
	u8 i = 0;
	u8 *BssidMacAddr = NULL;
	int ret =0;

	DstMacAddr = ieee80211_get_DA(hdr);
	if ((0x01 != DstMacAddr[0])||(0x00 != DstMacAddr[1])||(0x5e != DstMacAddr[2])){/*multicast ip Addr range:239.0~239.xx ||(0x76 <= DstMacAddr[3])*/
		return -1;
	}

	if ((0 == DstMacAddr[3])&&(uclsdsyncode!= DstMacAddr[4])){/*Sync Frame Must be 1:00:5e:00:64:xx*/
		return -1;
	}
	//printf("Multicast ADDR:%x:%x:%x:%x:%x:%x\n", DstMacAddr[0], DstMacAddr[1], DstMacAddr[2], DstMacAddr[3], DstMacAddr[4], DstMacAddr[5]);

	SrcMacAddr = ieee80211_get_SA(hdr);
#if CONFIG_ONESHOT_MAC_FILTER	
	if (0 == tls_filter_module_srcmac(SrcMacAddr)){
		return -1;
	}
#endif
	if (NULL == aulsddata){
		return -1;
	}

	if (tls_wifi_compare_mac_addr(SrcMacAddr)){
		lsdIndex = DstMacAddr[3];
		lsdData1 = DstMacAddr[4];
		lsdData	 = DstMacAddr[5];
		if (lsdIndex > 0){		/*Save Data*/
			index = lsdIndex-1;
			if (0 == ((ullsddatavalid[index/32]>>(index%32))&0x1)){
				aulsddata[2*index] = lsdData1;
				aulsddata[2*index+1] = lsdData;
				ullsddatavalid[index/32] |= 1 << (index%32);
			}
		}

		if ((lsdIndex == 0 )&&(lsdData1==uclsdsyncode)&&((uclsddatalen == 0xFF)||(lsdData != uclsddatalen))){
			if ((lsdData != uclsddatalen) && (uclsddatalen != 0xFF)){
				for (i = 0; i < uclsddatalen; i++){
					if (ullsddatavalid[i/32]>>(i%32)&0x01){
						aulsddata[2*i] = 0;
						aulsddata[2*i+1] = 0;
						ullsddatavalid[i/32] &= ~(1<<(i%32));
					}
				}
			}
			uclsddatalen = lsdData;
		}
	}else{
		return -1;
	}

	if (0 == guchandshakeflag){ /*sync*/
		if ((0 == DstMacAddr[3])&&(uclsdsyncode == DstMacAddr[4])){
			++lsdhandshakecnt;
		}
		if (lsdhandshakecnt >= HANDSHAKE_CNT){
			guchandshakeflag = 1;
			if (ieee80211_has_tods(hdr->frame_control)){
				BssidMacAddr = hdr->addr1;
			}else if (ieee80211_has_fromds(hdr->frame_control)){
				BssidMacAddr = hdr->addr2;
			}
			if (BssidMacAddr){
				memcpy(gucbssidData, BssidMacAddr, ETH_ALEN);
			}
			printf("[LSD:%d]gSrcMac:%x:%x:%x:%x:%x:%x\n",tls_os_get_time(), gSrcMac[0], gSrcMac[1], gSrcMac[2], gSrcMac[3], gSrcMac[4], gSrcMac[5]);
		}
	}else{	/*data handle*/
		if ((uclsddatalen != 0)&&(uclsddatalen != 0xFF)){
			for (i = 0; i < (uclsddatalen+1)/2; i++){
				if ((ullsddatavalid[i/32]>>(i%32))&0x1){
					continue;
				}
				break;
			}

			if (i == (uclsddatalen+1)/2){
				aulsddata[uclsddatalen] ='\0';
				gucssidData[0] = '\0';
				gucCustomData[0][0] = '\0';
				memset(gucpwdData, 0, 65);
			//	printf("[LSD]aulsddat[%d]:%s\n",uclsddatalen, aulsddata);
				ret = tls_wifi_decode_new_oneshot_data(aulsddata,gucpwdData, gucbssidData, gucssidData, gucCustomData[0]);
				if (0==ret){
				//	printf("[LSD]recv ok:%d\n", tls_os_get_time());
					if ((0 == tls_is_zero_ether_addr(gucbssidData))&&(gucssidData[0] != '\0')){
						gucbssidokflag = 1;
						gucssidokflag = 1;
						gucpwdokflag = 1;
					}else if (gucssidData[0] != '\0'){
						gucssidokflag = 1;
						gucbssidokflag = 0;
						gucpwdokflag = 1;
					}else if (gucCustomData[0][0] != '\0'){
						tls_wifi_clear_oneshot_data();
						guchandshakeflag = 0;
						gchancfm = 0xFF;
					}

					if (((1== gucssidokflag)||(1 == gucbssidokflag)) && (1 == gucpwdokflag)){
						if (gucbssidokflag&&gucssidokflag){
							printf("[LSD]SSID:%s\n", gucssidData);
							printf("[LSD]BSSID:%x:%x:%x:%x:%x:%x\n",	gucbssidData[0],  gucbssidData[1],	gucbssidData[2],  gucbssidData[3],	gucbssidData[4],  gucbssidData[5]); 	
							printf("[LSD]PASSWORD:%s\n", gucpwdData);
							tls_wifi_oneshot_connect_by_ssid_bssid(gucssidData, gucbssidData, gucpwdData);
						}else if(gucssidokflag&&(gucssidData[0] != '\0')){
							printf("[LSD]SSID:%s\n", gucssidData);		
							printf("[LSD]PASSWORD:%s\n", gucpwdData);
							tls_wifi_oneshot_connect(gucssidData, gucpwdData);
						}
					}
				}else{
					tls_wifi_clear_oneshot_data();
					guchandshakeflag = 0;
					gchancfm = 0xFF;
				}
				return 0;
			}
		}
	}
	return -1;
}
#endif
/*END CONFIG_UDP_ONE_SHOT*/
#endif
#if TLS_CONFIG_AP_MODE_ONESHOT
int soft_ap_create(void)
{
	struct tls_softap_info_t apinfo;
	struct tls_ip_info_t ipinfo;
	u8 ret=0;
	u8 ssid_set = 0;
	char ssid[33];
	u8 mac_addr[6];
    
    tls_get_mac_addr(mac_addr);
    ssid[0]='\0';
    u8 ssid_len = sprintf(ssid, "%s_%02x%02x", ONESHOT_AP_NAME, mac_addr[4], mac_addr[5]);
	tls_oneshot_save_ip_param();

	tls_param_get(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)0);
	if (0 == ssid_set)
	{
		ssid_set = 1;
		tls_param_set(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)1); /*设置BSSID广播标志*/
	}
	memset(&apinfo, 0, sizeof(struct tls_softap_info_t));
	MEMCPY(apinfo.ssid, ssid, ssid_len);
	apinfo.ssid[ssid_len]='\0';
	
	apinfo.encrypt = 0;  /*0:open, 1:wep64, 2:wep128*/
	apinfo.channel = 5; /*channel random*/
	/*ip配置信息:ip地址，掩码，dns名称*/
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
	//printf("\n ap create %s ! \n", (ret == WM_SUCCESS)? "Successfully" : "Error");

	return ret;
}

err_t  socket_recive_cb(u8 skt_num, struct pbuf *p, err_t err)
{
	int len = p->tot_len;
	int datalen = 0;
	char *pStr = NULL;
	char *pEnd;
	char *LenStr = NULL;
	int ret  = 0;
    //printf("socket recive data\n");
	if (0 == gucRawValid){
		gucRawValid = 1;
	    if(p->tot_len > SOCKET_RX_DATA_BUFF_LEN)
	    {
	    	len = SOCKET_RX_DATA_BUFF_LEN;
	    }
		pStr = tls_mem_alloc(len+1);
		if (pStr){
		    pbuf_copy_partial(p, pStr, len, 0);
			//printf("pStr:%s\n", pStr);
			pEnd = strstr(pStr, "\r\n");
			if (pEnd){
				datalen = pEnd - pStr;
				LenStr = tls_mem_alloc(datalen+1);
				memcpy(LenStr, pStr, datalen);
				LenStr[datalen] = '\0';
				ret = strtodec(&datalen,LenStr);
				tls_mem_free(LenStr);
				LenStr = NULL;
				if (ret == 0){
					//printf("trans datalen:%d\n", datalen);
					strncpy(sock_rx->sock_rx_data, pEnd + 2, datalen);
					sock_rx->sock_rx_data[datalen] = '\0';
					pEnd = NULL;
				    sock_rx->sock_data_len = datalen;
				   // printf("\nsock recive data = %s\n",sock_rx->sock_rx_data);
				   tls_os_queue_send(ap_sock_s_q, (void *)AP_SOCK_S_MSG_SOCKET_RECEIVE_DATA, 0);  
				}
	   		}
			tls_mem_free(pStr);
			pStr = NULL;
		}
	    if (p){
	       pbuf_free(p);
	    }
	}
    return ERR_OK;
}

int create_tcp_server_socket(void)
{    
    skt_descp = (struct tls_socket_desc *)tls_mem_alloc(sizeof(struct tls_socket_desc));
    if(skt_descp == NULL)
    {
        return -1;
    }
    memset(skt_descp, 0, sizeof(struct tls_socket_desc));
    
    sock_rx = (ST_Sock_Recive *)tls_mem_alloc(sizeof(ST_Sock_Recive));
    if(sock_rx == NULL)
    {
        tls_mem_free(skt_descp);
        skt_descp = NULL;
        return -1;
    }
    memset(sock_rx, 0, sizeof(ST_Sock_Recive));
    
    sock_rx->sock_rx_data = tls_mem_alloc(SOCKET_RX_DATA_BUFF_LEN*sizeof(char));
    if(sock_rx->sock_rx_data == NULL)
    {
        tls_mem_free(sock_rx);
        tls_mem_free(skt_descp);
        sock_rx = NULL;
        skt_descp = NULL;
        return -1;
    }
    memset(sock_rx->sock_rx_data, 0, sizeof(255*sizeof(char)));
    
	skt_descp->protocol = SOCKET_PROTO_TCP;
	skt_descp->cs_mode = SOCKET_CS_MODE_SERVER;
	skt_descp->port = SOCKET_SERVER_PORT;
    skt_descp->recvf = socket_recive_cb;
	sock_rx->socket_num = tls_socket_create(skt_descp);
	//printf("sck_num =　%d\n",sock_rx->socket_num);
    return WM_SUCCESS;
}

void free_socket(void)
{
	if (sock_rx == NULL){
		return;
	}
	if (sock_rx->socket_num == 0){
		return ;
	}
    tls_socket_close(sock_rx->socket_num);
	sock_rx->socket_num = 0;
    if(NULL != skt_descp)
    {
        tls_mem_free(skt_descp);
        skt_descp = NULL;
    }

    if(NULL != sock_rx->sock_rx_data)
    {
        tls_mem_free(sock_rx->sock_rx_data);
        sock_rx->sock_rx_data = NULL;
		sock_rx->sock_data_len = 0;
    }

        tls_mem_free(sock_rx);
        sock_rx = NULL;
}

static void ap_sock_s_net_status_changed_event(u8 status )
{
	u8 wifi_mode;
	if (0 == tls_wifi_get_oneshot_flag()){
		return;
	}

	tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void* )&wifi_mode, true);
	switch(status)
	{
		case NETIF_WIFI_JOIN_SUCCESS:
			if (IEEE80211_MODE_AP == wifi_mode){
				tls_os_queue_send(ap_sock_s_q, (void *)AP_SOCK_S_MSG_SOCKET_CREATE, 0);
			}
			break;
		case NETIF_WIFI_JOIN_FAILED:
			if (IEEE80211_MODE_AP == wifi_mode){
				tls_os_queue_send(ap_sock_s_q, (void *)AP_SOCK_S_MSG_WJOIN_FAILD, 0);
			}
			break;
		default:
			break;
	}
}

static void ap_sock_s_task(void *p);
int CreateApSockServerTask(void)
{
	static u8 taskcreatflag = 0;

	if (0 == taskcreatflag){
		taskcreatflag = 1;
	    ap_sock_s_queue = (void *)tls_mem_alloc(sizeof(tls_os_queue_t)*AP_SOCK_S_QUEUE_SIZE);
	    if(ap_sock_s_queue == NULL)
	    {
	        return WM_FAILED;
	    }
	    memset(ap_sock_s_queue, 0, sizeof(tls_os_queue_t)*AP_SOCK_S_QUEUE_SIZE);
	    
	    ApSockSTaskStk = (OS_STK *)tls_mem_alloc(sizeof(OS_STK)*AP_SOCK_S_TASK_SIZE);
	    if(ApSockSTaskStk == NULL)
	    {
	        tls_mem_free(ap_sock_s_queue);
	        ap_sock_s_queue = NULL;
	        return WM_FAILED;
	    }
	    memset(ApSockSTaskStk, 0, sizeof(OS_STK)*AP_SOCK_S_TASK_SIZE);
	    
		tls_os_queue_create(&ap_sock_s_q,
	            ap_sock_s_queue,
	            AP_SOCK_S_QUEUE_SIZE, 0);

		tls_os_task_create(NULL, NULL,
				ap_sock_s_task,
	                    NULL,
	                    (void *)ApSockSTaskStk,          /* 任务栈的起始地址 */
	                    AP_SOCK_S_TASK_SIZE * sizeof(u32), /* 任务栈的大小     */
	                    AP_SOCKET_S_TASK_PRIO,
	                    0);
	}

    tls_netif_add_status_event(ap_sock_s_net_status_changed_event);
    soft_ap_create();

	return WM_SUCCESS;
}

static void ap_sock_s_task(void *p)
{
    void *msg;
	int ret = -1;
    
    for(;;)
    {
        tls_os_queue_receive(ap_sock_s_q, (void **)&msg, 0, 0);
        switch((u32)msg)
		{
			case AP_SOCK_S_MSG_SOCKET_RECEIVE_DATA:
				/*收到数据，自行处理*/
				gucssidData[0] = '\0';
				memset(gucbssidData, 0, 6);
				ret = tls_wifi_decode_new_oneshot_data((const u8 *)sock_rx->sock_rx_data,gucpwdData, gucbssidData, gucssidData, NULL);
				if (0 == ret){
					if ((0 == tls_is_zero_ether_addr(gucbssidData))&&(gucssidData[0] == '\0')){
						gucbssidokflag = 1;
						gucpwdokflag = 1;
					}else{
						gucssidokflag = 1;
						gucpwdokflag = 1;
					}
					
					tls_wifi_send_oneshotinfo((const u8 *)sock_rx->sock_rx_data, sock_rx->sock_data_len, APSKT_MAX_ONESHOT_NUM);
					if (((1== gucssidokflag)||(1 == gucbssidokflag)) && (1 == gucpwdokflag)){
						if (gucbssidokflag){
							printf("[SOCKB]BSSID:%x:%x:%x:%x:%x:%x\n",  gucbssidData[0],  gucbssidData[1],  gucbssidData[2],  gucbssidData[3],  gucbssidData[4],  gucbssidData[5]);		
							printf("[SOCKB]PASSWORD:%s\n", gucpwdData);
							tls_wifi_oneshot_connect_by_bssid(gucbssidData, gucpwdData);
						}else {
							printf("[SOCKS]SSID:%s\n", gucssidData);		
							printf("[SOCKS]PASSWORD:%s\n", gucpwdData);
							tls_wifi_oneshot_connect(gucssidData, gucpwdData);
						}
					}
				}
				gucRawValid = 0;

				break;                
            case AP_SOCK_S_MSG_SOCKET_CREATE:
                create_tcp_server_socket();
                break;
            case AP_SOCK_S_MSG_WJOIN_FAILD:
                if((sock_rx)&&(sock_rx->socket_num > 0))
                {
                //	printf("free_socket\n");
                    free_socket();
                    sock_rx->socket_num = 0;
                }
                break;
			default:
				break;
		}
    }
}
#endif
#if CONFIG_ONESHOT_MAC_FILTER
static u8 gauSrcmac[ETH_ALEN]= {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
void tls_filter_module_srcmac_show(void){
	printf("num:%d\n", sizeof(gauSrcmac)/ETH_ALEN);
}

int tls_filter_module_srcmac(u8 *mac){
	int ret = 0;
	u8 localmac[6];

	if (0 == tls_is_zero_ether_addr(gauSrcmac)){
		tls_get_mac_addr((u8 *)(&localmac));
		if ((0 == memcmp(gauSrcmac, mac, ETH_ALEN))&&(0 != memcmp(localmac, mac, ETH_ALEN))){
			ret = 1;
			//break;
		}
	}else{
		ret = 1;
	}

	return ret;
}
#endif
#if TLS_CONFIG_UDP_ONE_SHOT
extern void ieee802_11_parse_elems(u8 *start, u32 len, struct ieee802_11_elems *elems);
static __inline u8 ieee80211_get_ap_chan(struct ieee80211_hdr *hdr, u32 data_len)
{
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)hdr;
    u16 fc = mgmt->frame_control;
    bool beacon = false;
    struct ieee802_11_elems elems;
    u8 *elements;
    u32 baselen;
	beacon = ieee80211_is_beacon(fc);
	if (beacon){
		baselen = (u8 *)mgmt->u.beacon.variable - (u8 *)mgmt;;
		elements = mgmt->u.beacon.variable;
		ieee802_11_parse_elems(elements, data_len - baselen, &elems); 		
		if (elems.ds_params && elems.ds_params_len == 1){
			if (!tls_is_zero_ether_addr(gucbssidData)
				&&(0 == tls_compare_ether_addr(gucbssidData, mgmt->bssid))){
				gchancfm = (elems.ds_params[0]-1);
			}
			return (elems.ds_params[0]-1);
		}
	}
	return 0xFF;
}
#endif

u8 tls_wifi_dataframe_recv(struct ieee80211_hdr *hdr, u32 data_len)
{
	u8 chanindex = 0;
	u8 i = 0;
	u8 tmp = 0;

	if (tls_wifi_get_oneshot_flag()== 0){
		return 1;
	}

#if TLS_CONFIG_UDP_ONE_SHOT
	if (gchancfm == 0xFF){
		chanindex = ieee80211_get_ap_chan(hdr, data_len);
		if ((chanindex < 13)&&(0 == (usIsDataIn&(1<<chanindex)))){
			usIsDataIn |= 1<<chanindex;
			for (i = 0; i < uctotalchannum; i++){
				if (chanindex < airwifichan[i]){
					tmp = airwifichan[i];
					airwifichan[i] = chanindex;
					chanindex = tmp;
				}
			}
			airwifichan[uctotalchannum] = chanindex;
			uctotalchannum++;
			//printf("uctotalchannum:%d, %d,Time:%d\n", uctotalchannum, chanindex,tls_os_get_time());
			return 1;
		}
	}
#endif

	if (0 == ieee80211_is_data(hdr->frame_control)){
		return 1;
	}

#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
    tls_airkiss_recv((u8 *)hdr, data_len);
#endif

	if ((IEEE80211_FCTL_VERS|IEEE80211_STYPE_CFACKPOLL) == (hdr->frame_control&(IEEE80211_STYPE_CFACKPOLL|IEEE80211_FCTL_VERS)))
	{
#if CONFIG_ONESHOT_MAC_FILTER	
		if (1 == tls_filter_module_srcmac(hdr->addr2)){
#endif	
			if (1 == tls_wifi_decrypt_data((u8 *)hdr)){
				if (((1== gucssidokflag)||(1 == gucbssidokflag)) && (1 == gucpwdokflag)){
					if (gucbssidokflag&&gucssidokflag){
						printf("[PB]SSID:%s\n", gucssidData);	
						printf("[PB]BSSID:%x:%x:%x:%x:%x:%x\n",  gucbssidData[0],  gucbssidData[1],  gucbssidData[2],  gucbssidData[3],  gucbssidData[4],  gucbssidData[5]);		
						printf("[PB]PASSWORD:%s\n", gucpwdData);
						tls_wifi_oneshot_connect_by_ssid_bssid(gucssidData, gucbssidData, gucpwdData);
					}else if (1 == gucssidokflag){
						printf("[PB]SSID:%s\n", gucssidData);		
						printf("[PB]PASSWORD:%s\n", gucpwdData);
						tls_wifi_oneshot_connect(gucssidData, gucpwdData);
					}else{
						gucssidokflag = 0;
						gucbssidokflag = 0;
						gucpwdokflag = 0;
						memset(gucssidData, 0, 33);
						memset(gucbssidData, 0, 6);
						memset(gucpwdData, 0, 65);
						memset(gSrcMac, 0, ETH_ALEN);
						tls_wifi_clear_oneshot_data();
					}
#if TLS_CONFIG_AP_MODE_ONESHOT					
					gucRawValid = 0;
#endif
				}
			}
#if CONFIG_ONESHOT_MAC_FILTER			
		}
#endif		
		return 1;
	}


#if TLS_CONFIG_UDP_ONE_SHOT
#if TLS_CONFIG_UDP_JD_ONESHOT
	tls_wifi_jd_oneshot(hdr);
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT
	tls_wifi_lsd_oneshot(hdr);
#endif
#endif

	return 1;
}


void tls_wifi_stop_oneshot(void)
{
#if TLS_CONFIG_UDP_ONE_SHOT	
#if TLS_ONESHOT_SWITCHCHANTIM_CFG
    tls_os_timer_stop(gWifiSwitchChanTim);
#endif
    gchancfm = 0xFF;
	guchandshakeflag = 0;
	memset(gSrcMac, 0, ETH_ALEN);
	tls_wifi_clear_oneshot_data();
#if TLS_CONFIG_UDP_JD_ONESHOT
	if (aujddata){
		tls_mem_free(aujddata);
		aujddata = NULL;
	}
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT
	if (aulsddata){
	    tls_mem_free(aulsddata);
		aulsddata = NULL;
	}
#endif
#endif

 	gucssidokflag = 0;
	gucbssidokflag = 0;
	gucpwdokflag = 0;
#if TLS_CONFIG_AP_MODE_ONESHOT	
	free_socket();
#endif
	tls_wifi_data_recv_cb_register(NULL);
#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
    tls_airkiss_stop();
#endif
}

void tls_wifi_start_oneshot(void)
{
    gucssidokflag = 0;
	gucbssidokflag = 0;
	gucpwdokflag = 0;
	memset(gucssidData, 0, 33);
	memset(gucbssidData, 0, 6);
	memset(gucpwdData, 0, 65);
#if TLS_CONFIG_AP_MODE_ONESHOT
	CreateApSockServerTask();
#endif
#if TLS_CONFIG_UDP_ONE_SHOT
	gchancfm = 0xFF;
	guchandshakeflag = 0;
#if TLS_CONFIG_UDP_JD_ONESHOT
	if (NULL == aujddata){
		aujddata = tls_mem_alloc(128);
	}
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT
	if (NULL == aulsddata){
		aulsddata = tls_mem_alloc(256);
	}
#endif
	memset(gSrcMac, 0, ETH_ALEN);
	tls_wifi_clear_oneshot_data();

#if TLS_ONESHOT_SWITCHCHANTIM_CFG	
	if (NULL == gWifiSwitchChanTim){
		tls_os_timer_create(&gWifiSwitchChanTim,tls_wifi_switch_channel_tim, NULL,TLS_ONESHOT_SWITCH_TIMER_MAX,false,NULL);
	}

	if (gWifiSwitchChanTim)
	{
		tls_os_timer_stop(gWifiSwitchChanTim);
		tls_os_timer_change(gWifiSwitchChanTim, TLS_ONESHOT_SWITCH_TIMER_MAX);
	}
#endif
#endif
	tls_wifi_data_recv_cb_register((tls_wifi_data_recv_callback)tls_wifi_dataframe_recv);
#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
    tls_airkiss_start();
#endif
}


/*************************************************************************** 
* Function: tls_wifi_set_oneshot_flag 
*
* Description: This function is used to set oneshot flag.
* 
* Input: flag 0:one shot  closed
* 		      1:one shot  open
* Output: None 
* 
* Return: None
* 
* Date : 2014-6-11 
****************************************************************************/ 
void tls_wifi_set_oneshot_flag(u8 flag)
{
	if (1 == flag)
	{
		if (guconeshotflag != 1)
		{
			guconeshotflag = flag;
			tls_wifi_disconnect();

#if (!TLS_CONFIG_AP_MODE_ONESHOT || TLS_CONFIG_AIRKISS_MODE_ONESHOT)
			tls_wifi_set_listen_mode(1);
#endif
			tls_wifi_start_oneshot();
		}
	}
	else
	{
#if TLS_CONFIG_AP_MODE_ONESHOT	
		if (guconeshotflag){
			tls_wifi_wait_disconnect();
		}
#endif		
		guconeshotflag = flag;	
		tls_wifi_set_listen_mode(0);
		tls_wifi_stop_oneshot();
	}
}

/*************************************************************************** 
* Function: 	tls_wifi_get_oneshot_flag 
*
* Description: This function is used to get oneshot flag.
* 
* Input:  		None 
* 
* Output: 	None 
* 
* Return: 	
*			0:one shot  closed
* 		    	1:one shot  open
* 
* Date : 2014-6-11 
****************************************************************************/ 
int tls_wifi_get_oneshot_flag(void)
{
	return guconeshotflag;
}

