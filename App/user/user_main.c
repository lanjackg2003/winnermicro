#include "user_main.h"
#include "zc_hf_adpter.h"
// user data
static USER_DEVICE_INFO gstUserDeviceInfo;
// task
static tls_os_queue_t *gsUserTaskQueue = NULL;
static void *UserTaskQueue[USER_QUEUE_SIZE];
static OS_STK UserTaskStk[USER_TASK_SIZE];
// key scan
static u8 gsKeyPreStatus = 0;
static u8 gsKeyStatus = 0;

// tcp client param
#define TCP_REMOTE_PORT 1000                // 用户tcp client 连接远程端口
static u8 TcpRemoteIp[4] = {192,168,31,168};            // TCP 远程服务器的IP
static struct tls_socket_desc raw_socket_c_desc;        // socket client info

// tcp server param
#define TCP_LOCAL_PORT      2000                // 用户tcp server 本地监听端口
struct tls_socket_desc raw_socket_s_desc;           // socket server info

// udp broadcast param
#define UDP_BROAD_PORT  65534               // udp 广播端口号

static void KeyScanTimerProc(void);
static void UdpBroadTimerProc(void);
static void UserWlanStatusChangedEvent(INT8U status);
static int CreateUserTask(void);
static void UserTaskProc(void);
static void uart_proc_data(void);
static INT16S UserUartRxCallback(char *buf, u16 len);
extern void ZC_Moudlefunc(u8 *pu8Data, u32 u32DataLen); 
/***************************************************************************
* Description: 初始化用户的设备 相关
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
void UserDeviceInit(void)
{
    INT8S autoconnect;

    memset((void *)&gstUserDeviceInfo, 0, sizeof(USER_DEVICE_INFO));
    // check autoconnect
    tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_GET, &autoconnect);
    if(WIFI_AUTO_CNT_OFF == autoconnect)
    {
        autoconnect = WIFI_AUTO_CNT_ON;
        // 设置自动重连
        tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_SET, &autoconnect);
    }

    // create static user task
    CreateUserTask();
}

/***************************************************************************
* Description:udp 广播timer处理函数
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static void UdpBroadTimerProc(void)
{
    tls_os_queue_send(gsUserTaskQueue, (void *)MSG_TIMER, 0);
}
/***************************************************************************
* Description: 网络状态变化回调函数
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static void UserWlanStatusChangedEvent(INT8U status)
{
    switch(status)
    {
        case NETIF_WIFI_JOIN_SUCCESS:
            printf("houxf debug NETIF_WIFI_JOIN_SUCCESS\r\n");
            break;
        case NETIF_WIFI_JOIN_FAILED:
            printf("houxf debug NETIF_WIFI_JOIN_FAILED\r\n");
            break;
        case NETIF_WIFI_DISCONNECTED:
            printf("houxf debug NETIF_WIFI_DISCONNECTED\r\n");
            tls_os_queue_send(gsUserTaskQueue,(void *)MSG_NET_DOWN,0);
            break;
        case NETIF_IP_NET_UP:
            printf("houxf debug NETIF_IP_NET_UP\r\n");
            tls_os_queue_send(gsUserTaskQueue, (void *)MSG_NET_UP, 0);
            break;
        default:
            break;
    }
}
/***************************************************************************
* Description: 创建用户任务
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static int CreateUserTask(void)
{
    tls_os_queue_create(&gsUserTaskQueue, &UserTaskQueue, USER_QUEUE_SIZE, 0);
    tls_os_task_create(NULL, NULL, UserTaskProc, NULL,
                    (void *)UserTaskStk,                     /* 任务栈的起始地址 */
                    USER_TASK_SIZE * sizeof(u32),        /* 任务栈的大小     */
                    USER_TASK_PRO,
                    0);
    return WM_SUCCESS;
}

/***************************************************************************
* Description: 用户任务处理回调函数
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static void UserTaskProc(void)
{
    void *msg;
    struct tls_ethif * ethif;
// 配置用户串口
    tls_user_uart_set_baud_rate(USER_UART_BAUDRATE);
    tls_uart_cfg_user_mode();
    tls_user_uart_rx_register(UserUartRxCallback);
    // 注册网络状态回调函数
    tls_netif_add_status_event(UserWlanStatusChangedEvent);
    for(;;)
    {
        tls_os_queue_receive(gsUserTaskQueue, (void **)&msg, 0, 0);
        switch((u32)msg)
        {
            case MSG_NET_UP:                // 加网成功
                printf("fengq: MSG_NET_UP\n");
                ethif = tls_netif_get_ethif();
			    printf("\nip=%d.%d.%d.%d\n",ip4_addr1(&ethif->ip_addr.addr),ip4_addr2(&ethif->ip_addr.addr),
		        ip4_addr3(&ethif->ip_addr.addr),ip4_addr4(&ethif->ip_addr.addr));
                memcpy(&g_u32GloablIp,ethif->ip_addr.addr,4);
                HF_WakeUp();
                break;

            case MSG_NET_DOWN:              // 网络断开
                printf("fengq: MSG_NET_DOWN\n");

                HF_Sleep();
                HF_BcInit();
                break;

            case MSG_ONESHOT:               // 启动一键配置
                printf("fengq: MSG_ONESHOT\n");
                tls_wifi_set_oneshot_flag(1);
                break;

            case MSG_SK_CLIENT_ERR:         // socket 断开
                tls_os_time_delay(200);
//                printf("fengq: MSG_SK_CLIENT_ERR\n");

                break;

            case MSG_SK_CLIENT_RX_DATA: // socket client 收到数据客户解析自己的数据
                break;

            case MSG_SK_SERVER_ERR:         // socket 断开
//                printf("fengq: MSG_SK_SERVER_ERR\n");
                break;

            case MSG_SK_SERVER_RX_DATA: // socket client 收到数据客户解析自己的数据
                break;

            case MSG_TIMER:
                break;
            case MSG_UART_RX_DATA:
			uart_proc_data();
			break;
            default:
                break;
        }
    }
}

/*************************************************************************** 
* Description:串口接收回调函数
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/ 
static INT16S UserUartRxCallback(char *buf, u16 len)
{
    INT16U temp;
	INT16U size;
	INT16U wcount;
//    printf("URC=%d\r\n",len);
    if(len == 0){return;}
	if(gstUserDeviceInfo.wptr > gstUserDeviceInfo.rptr)
	{
		size = TCP_TXBUFF_MAX - gstUserDeviceInfo.wptr + gstUserDeviceInfo.rptr;
	}
	else if(gstUserDeviceInfo.wptr < gstUserDeviceInfo.rptr)
	{
		size = gstUserDeviceInfo.rptr - gstUserDeviceInfo.wptr;
	}
	else if(gstUserDeviceInfo.wptr == gstUserDeviceInfo.rptr)
	{
		if(gstUserDeviceInfo.overflag)
		{
			printf("houxf debug over buf \r\n");
			size = 0;
			if(gstUserDeviceInfo.MsgNum < 1)
			{
				tls_os_queue_send(gsUserTaskQueue, (void *)MSG_UART_RX_DATA, 0);
				gstUserDeviceInfo.MsgNum ++;
			}
			return -1;
		}
		else
		{
			size = TCP_TXBUFF_MAX;
		}
	}
	if(size >= len)
	{
		wcount = len;
	}
	else
	{
		gstUserDeviceInfo.overflag = 1;	/*???????*/
		wcount = size;
		printf("\nrx buf full\n");
	}
	
	if(gstUserDeviceInfo.wptr + wcount < TCP_TXBUFF_MAX)
	{	
		memcpy(gstUserDeviceInfo.uart_rx + gstUserDeviceInfo.wptr, buf, wcount);
		gstUserDeviceInfo.wptr += wcount;
	}
	else
	{
		temp = TCP_TXBUFF_MAX - gstUserDeviceInfo.wptr;
		memcpy(gstUserDeviceInfo.uart_rx+ gstUserDeviceInfo.wptr, buf, temp);
		memcpy(gstUserDeviceInfo.uart_rx, buf + temp, wcount - temp);
		gstUserDeviceInfo.wptr = wcount - temp;
	}

	tls_os_queue_send(gsUserTaskQueue, (void *)MSG_UART_RX_DATA, 0);
	//gstUserDeviceInfo.MsgNum ++;		

	return 0;
}

/*************************************************************************** 
* Description: socket 
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/ 
static void uart_proc_data(void)
{
	INT16U len, wptr;	
    int cpu_sr;		
    
    cpu_sr = tls_os_set_critical();
    wptr = gstUserDeviceInfo.wptr;
	if(gstUserDeviceInfo.rptr < wptr)
	{
		len = wptr - gstUserDeviceInfo.rptr;	
		memcpy(gstUserDeviceInfo.tx_buff, gstUserDeviceInfo.uart_rx + gstUserDeviceInfo.rptr, len);
		gstUserDeviceInfo.rptr += len;		
		gstUserDeviceInfo.overflag = 0;
	}
	else if(gstUserDeviceInfo.rptr > wptr ||(gstUserDeviceInfo.rptr == wptr &&  gstUserDeviceInfo.overflag))
	{
		len = TCP_TXBUFF_MAX - gstUserDeviceInfo.rptr;
		memcpy(gstUserDeviceInfo.tx_buff, gstUserDeviceInfo.uart_rx + gstUserDeviceInfo.rptr, len);
		memcpy(gstUserDeviceInfo.tx_buff+ len, gstUserDeviceInfo.uart_rx, wptr);
		len += wptr;
		gstUserDeviceInfo.rptr = wptr;
		gstUserDeviceInfo.overflag = 0;
	}
    else
    {
        return; 
     }
    tls_os_release_critical(cpu_sr);

	//if(gstUserDeviceInfo.MsgNum)
	{     
        ZC_Moudlefunc(gstUserDeviceInfo.tx_buff, len);
		//gstUserDeviceInfo.MsgNum--;
	}
}

