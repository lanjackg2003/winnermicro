/***************************************************************************** 
* 
* File Name : wm_demo_task.c
* 
* Description: demo task
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-14
*****************************************************************************/ 
#include <string.h>
#include "wm_include.h"
#if (DEMO_KII || DEMO_ALLJOYN_LED)
#include "light_if.h"
#endif

#if DEMO_CONSOLE
#define    DEMO_TASK_SIZE      768
tls_os_queue_t *demo_q = NULL;
void *demo_queue[DEMO_QUEUE_SIZE];
static OS_STK DemoTaskStk[DEMO_TASK_SIZE]; 
ST_Demo_Sys gDemoSys;


void demo_console_task(void *sdata);

extern void demo_uart_malloc(void);
extern void demo_uart_open(void);
extern int demo_uart_cmd_parse(ST_Demo_Sys *sys);
extern int socket_raw_send_data_demo(ST_Demo_Sys *sys);
extern int socket_std_send_data_demo(ST_Demo_Sys *sys);
extern int demo_console_show_help(void);


void CreateDemoTask(void)
{
	memset(&gDemoSys, 0 ,sizeof(ST_Demo_Sys));
	tls_os_queue_create(&demo_q,
            &demo_queue[0],
            DEMO_QUEUE_SIZE, 0);
	tls_os_task_create(NULL, NULL,
			demo_console_task,
                    (void *)&gDemoSys,
                    (void *)DemoTaskStk,          /* 任务栈的起始地址 */
                    DEMO_TASK_SIZE * sizeof(u32), /* 任务栈的大小     */
                    DEMO_TASK_PRIO,
                    0);
}

static void send_demo_function_data(char * buf, int wcount)
{
	int temp = 0;
	if(gDemoSys.wptr + wcount < DEMO_BUF_SIZE)
	{	
		//printf("\n1 rx\n");
		MEMCPY(gDemoSys.rxbuf+ gDemoSys.wptr, buf, wcount);
		gDemoSys.wptr += wcount;
	}
	else
	{
		//printf("\n2 rx\n");
		temp = DEMO_BUF_SIZE - gDemoSys.wptr;
		MEMCPY(gDemoSys.rxbuf+ gDemoSys.wptr, buf, temp);
		MEMCPY(gDemoSys.rxbuf, buf + temp, wcount - temp);
		gDemoSys.wptr = wcount - temp;
	}
	if(gDemoSys.MsgNum < 5)
	{
		tls_os_queue_send(demo_q,(void *)DEMO_MSG_UART_RECEIVE_DATA,0);
		gDemoSys.MsgNum ++;		
	}
	else
	{
		//printf("\n q =5\n");
	}
}

static void console_net_status_changed_event(u8 status )
{
	struct tls_ethif * ethif;
#if DEMO_DLNA_DMR
	char * buf;
	int temp, wcount;
#endif
#if DEMO_CLOUD
	u8 automode = 0;
#endif
	switch(status)
	{
		case NETIF_WIFI_JOIN_FAILED:
			printf("\njoin net failed\n");
			break;
		case NETIF_WIFI_JOIN_SUCCESS:
			printf("\njoin net success\n");
			break;
		case NETIF_IP_NET_UP:
			ethif = tls_netif_get_ethif();
			printf("\nip=%d.%d.%d.%d\n",ip4_addr1(&ethif->ip_addr.addr),ip4_addr2(&ethif->ip_addr.addr),
					ip4_addr3(&ethif->ip_addr.addr),ip4_addr4(&ethif->ip_addr.addr));
#if DEMO_DLNA_DMR
			buf = "t-dlnadmr";
			wcount = strlen(buf);
			send_demo_function_data(buf, wcount);
#endif
#if DEMO_CLOUD
			tls_wifi_auto_connect_flag( WIFI_AUTO_CNT_FLAG_GET, &automode);
			if(automode)
				send_demo_function_data("t-jdcloud", 9);
#endif
			break;
		case NETIF_WIFI_DISCONNECTED:
			printf("\nnet disconnected\n");
			break;
		default:
			break;
	}
}


int opentx = 1;

//该任务使用uart1 作为测试控制台，可以输入字符串命令测试其他的demo
//测试socket收发数据时，可以通过该控制台向外传输数据
void demo_console_task(void *sdata)
{
	ST_Demo_Sys *sys = (ST_Demo_Sys *)sdata;
	void *msg;
	int ret = 0;
	u8 automode = WIFI_AUTO_CNT_OFF;
#if DEMO_DLNA_DMR
	struct tls_param_key  key;
	struct tls_param_ssid ssid;
#endif

#if (DEMO_KII || DEMO_ALLJOYN_LED)
	lightIf_init();
#endif
	
	demo_console_show_help();
	//起demo之后清除自动联网，和自动工作模式，避免系统自动创建socket和socket demo冲突
#if !DEMO_CLOUD
	tls_wifi_auto_connect_flag( WIFI_AUTO_CNT_FLAG_SET, &automode);
	tls_param_set(TLS_PARAM_ID_AUTOMODE, (void *)&automode, true);
#endif
	tls_netif_add_status_event(console_net_status_changed_event);
#if DEMO_DLNA_DMR
	tls_param_get(TLS_PARAM_ID_SSID, (void *)&ssid, true);
	tls_param_get(TLS_PARAM_ID_KEY, (void *)&key, true);
	tls_wifi_connect(ssid.ssid, ssid.ssid_len, key.psk, key.key_length);
#endif
	demo_uart_malloc();
#if TLS_CONFIG_UART
#if TLS_CONFIG_HOSTIF
	tls_user_uart_set_baud_rate(115200);
#else
	if(WM_SUCCESS  != tls_uart_port_init(TLS_UART_1, NULL))
		return;
#endif
#endif	
	tls_os_queue_send(demo_q,(void *)DEMO_MSG_OPEN_UART, 0);
#if DEMO_CLOUD
	tls_wifi_auto_connect_flag( WIFI_AUTO_CNT_FLAG_GET, &automode);
	if(!automode)
		send_demo_function_data("t-jdcloud", 9);
#endif
	for(;;) 
	{
		tls_os_queue_receive(demo_q, (void **)&msg, 0, 0);
		//printf("\n msg =%d\n",msg);
		switch((u32)msg)
		{
			case DEMO_MSG_OPEN_UART:
				demo_uart_open();
				break;
			case DEMO_MSG_UART_RECEIVE_DATA:
				ret = demo_uart_cmd_parse(sys);	//解析其他demo的测试命令字
				if(DEMO_CONSOLE_CMD == ret)	//先进行命令解析，看是否是模拟的命令字
				{
					memset(sys->rxbuf , 0, DEMO_BUF_SIZE);	/*命令传输完成之后清buf*/
					sys->rptr = 0;
					sys->wptr = 0;
				}
				else if(DEMO_CONSOLE_SHORT_CMD == ret)
				{
					//param not passed all, do nothing.
				}
				else if(sys->socket_ok)		//配合socket demo做数据发送
				{
					if(sys->is_raw)
					{
						socket_raw_send_data_demo(sys);
					}
					else
					{
						socket_std_send_data_demo(sys);
					}
				}	
				if(sys->MsgNum)
					sys->MsgNum --;
				break;
			default:
				break;
		}
	}
}

#endif	//DEMO_CONSOLE

