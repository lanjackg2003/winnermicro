#include <string.h>
#include "wm_include.h"
#include "wm_http_fwup.h"

#if DEMO_CONNECT_NET
extern const char DEMO_ONESHOT[];
extern const char DEMO_CONNET[];
#define    DEMO_ONESHOT_TASK_SIZE      256
tls_os_queue_t *demo_oneshot_q = NULL;
void *demo_oneshot_queue[DEMO_QUEUE_SIZE];
static OS_STK DemoOneShotTaskStk[DEMO_ONESHOT_TASK_SIZE]; 
extern ST_Demo_Sys gDemoSys;
u8 ifoneshot = 0;

static void demo_oneshot_task(void *sdata);
static int CreateOneshotDemoTask(void);

static void con_net_status_changed_event(u8 status )
{
	switch(status)
	{
		case NETIF_IP_NET_UP:
			if(ifoneshot)	//如果是一键配置，给一键配置任务发送消息，消息处理中把MAC地址发给手机app
			{
				ifoneshot = 0;
				tls_os_queue_send(demo_oneshot_q,(void *)DEMO_MSG_SOCKET_CREATE,0);
			}
			break;
		default:
			break;
	}
}


//联网demo，根据参数判断是一键配置联网还是主动联网
//一键配置命令示例:t-oneshot
//主动联网命令示例:t-connet("ssid","pwd");
int DemoConnectNet(char *buf)
{	
	if(strstr(buf,DEMO_ONESHOT) != NULL)	//一键配置
	{
		ifoneshot = 1;
		CreateOneshotDemoTask();
	}
	else if(strstr(buf, DEMO_CONNET) != NULL)
	{
		char *p1 = NULL,*p2 = NULL;
		char ssid[64];
		char pwd[70];
		struct tls_param_ip ip_param;
		
		if(strchr(buf, ';') != NULL || strchr(buf,')') != NULL)		//收到了命令结束符
		{
			printf("\ninput:%s\n",buf);
			memset(ssid,0,sizeof(ssid));
			memset(pwd,0,sizeof(pwd));
			p1 = strchr(buf,'"');
			if(NULL == p1)
				return WM_FAILED;
			p2 = p1 +1;	//ssid的起始位置
			p1 = strchr(p2,'"');	//ssid的结束位置
			if(NULL == p1)
				return WM_FAILED;
			MEMCPY(ssid, p2, p1 - p2);
			printf("\nssid=%s\n",ssid);
			p2 = p1 + 1;
			p1 = strchr(p2,'"');	
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
			printf("\npassword=%s\n",pwd);
			tls_wifi_set_oneshot_flag(0);
			ifoneshot = 0;

			tls_param_get(TLS_PARAM_ID_IP, &ip_param, FALSE);
			ip_param.dhcp_enable = true;
			tls_param_set(TLS_PARAM_ID_IP, &ip_param, FALSE);
			
			tls_wifi_connect((u8 *)ssid, strlen(ssid), (u8 *)pwd, strlen(pwd));
			tls_netif_add_status_event(con_net_status_changed_event);
			printf("\nplease wait connect net......\n");
		}
		else
			return DEMO_CONSOLE_SHORT_CMD;
	}

	return WM_SUCCESS;
}


static int CreateOneshotDemoTask(void)
{
	tls_os_queue_create(&demo_oneshot_q,
            &demo_oneshot_queue,
            DEMO_QUEUE_SIZE, 0);
	tls_os_task_create(NULL, NULL,
			demo_oneshot_task,
                    (void *)&gDemoSys,
                    (void *)DemoOneShotTaskStk,          /* 任务栈的起始地址 */
                    DEMO_ONESHOT_TASK_SIZE * sizeof(u32), /* 任务栈的大小     */
                    DEMO_ONESHOT_TASK_PRIO,
                    0);

	return WM_SUCCESS;
}


static void demo_oneshot_task(void *sdata)
{
	//ST_Demo_Sys *sys = (ST_Demo_Sys *)sdata;
	void *msg;
	struct tls_param_ip ip_param;

	tls_param_get(TLS_PARAM_ID_IP, &ip_param, TRUE);
	ip_param.dhcp_enable = true;
	tls_param_set(TLS_PARAM_ID_IP, &ip_param, TRUE);

	tls_wifi_set_oneshot_flag(1);		/*一键配置使能*/
	tls_netif_add_status_event(con_net_status_changed_event);
	printf("\nwait one shot......\n");
	for(;;) 
	{
		tls_os_queue_receive(demo_oneshot_q, (void **)&msg, 0, 0);
		//printf("\n msg =%d\n",msg);
		switch((u32)msg)
		{
			case DEMO_MSG_WJOIN_SUCCESS:
				break;
				
			case DEMO_MSG_SOCKET_CREATE:
#if TLS_CONFIG_SOCKET_STD
				DemoStdSockOneshotSendMac();		//任选一个		
#endif
#if TLS_CONFIG_SOCKET_RAW
				//DemoRawSockOneshotSendMac();
#endif //TLS_CONFIG_SOCKET_RAW
				break;
				
			case DEMO_MSG_WJOIN_FAILD:
				break;
			default:
				break;
		}
	}

}

#endif //DEMO_CONNECT_NET

#if DEMO_CONSOLE
#if TLS_CONFIG_SOCKET_STD
//one shot联网成功之后，把MAC地址用广播包发送出去，通知手机app
void DemoStdSockOneshotSendMac(void)
{
	struct sockaddr_in pin;
	int idx;
	int socket_num;
	u8 mac_addr[8];

	memset(&pin, 0, sizeof(struct sockaddr));
	pin.sin_family=AF_INET;                 //AF_INET表示使用IPv4
	pin.sin_addr.s_addr=htonl(0xffffffffUL);  //IPADDR_BROADCAST
	pin.sin_port=htons(65534);
	socket_num = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	//printf("\nstd sk one shot sock num=%d\n",socket_num);

	memset(mac_addr,0,sizeof(mac_addr));
	tls_get_mac_addr(mac_addr);
	tls_os_time_delay(200);				
	for(idx = 0;idx < 3;idx++)
	{
		sendto(socket_num, mac_addr, 6, 0, (struct sockaddr *)&pin, sizeof(struct sockaddr));
		tls_os_time_delay(50);
		//printf("========> socket num=%d\n",socket_num);
	}
	closesocket(socket_num);
	//printf("\none shot success!\n");
}
#endif //TLS_CONFIG_SOCKET_STD
#if TLS_CONFIG_SOCKET_RAW
void DemoRawSockOneshotSendMac(void)
{
	int idx;
	int socket_num = 0;
	u8 mac_addr[8];
	struct tls_socket_desc socket_desc;

	memset(&socket_desc, 0, sizeof(struct tls_socket_desc));
	socket_desc.cs_mode = SOCKET_CS_MODE_CLIENT;
	socket_desc.protocol = SOCKET_PROTO_UDP;
	for(idx = 0; idx < 4; idx++){
		socket_desc.ip_addr[idx] = 255;
	}
	socket_desc.port = 65534;
	socket_num = tls_socket_create(&socket_desc);
	//printf("\nraw sk one shot sock num=%d\n",socket_num);
	
	memset(mac_addr,0,sizeof(mac_addr));
	tls_get_mac_addr(mac_addr);
	tls_os_time_delay(200);				
	for(idx = 0;idx < 3;idx ++)
	{
		tls_socket_send(socket_num,mac_addr, 6);
		tls_os_time_delay(50);
	}
	tls_socket_close(socket_num);
	socket_num = 0;	
	//printf("\none shot success!\n");
}
#endif //TLS_CONFIG_SOCKET_RAW

#endif

