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
#define TCP_REMOTE_PORT 1000                // �û�tcp client ����Զ�̶˿�
static u8 TcpRemoteIp[4] = {192,168,31,168};            // TCP Զ�̷�������IP
static struct tls_socket_desc raw_socket_c_desc;        // socket client info

// tcp server param
#define TCP_LOCAL_PORT      2000                // �û�tcp server ���ؼ����˿�
struct tls_socket_desc raw_socket_s_desc;           // socket server info

// udp broadcast param
#define UDP_BROAD_PORT  65534               // udp �㲥�˿ں�

static void KeyScanTimerProc(void);
static void UdpBroadTimerProc(void);
static void UserWlanStatusChangedEvent(INT8U status);
static int CreateUserTask(void);
static void UserTaskProc(void);
static void uart_proc_data(void);
static INT16S UserUartRxCallback(char *buf, u16 len);
extern void ZC_Moudlefunc(u8 *pu8Data, u32 u32DataLen); 
/***************************************************************************
* Description: ��ʼ���û����豸 ���
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
void UserDeviceInit(void)
{
    tls_os_timer_t *KeyScanTimer = NULL;
    INT8S autoconnect;

    memset((void *)&gstUserDeviceInfo, 0, sizeof(USER_DEVICE_INFO));
    // check autoconnect
    tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_GET, &autoconnect);
    if(WIFI_AUTO_CNT_OFF == autoconnect)
    {
        autoconnect = WIFI_AUTO_CNT_ON;
        // �����Զ�����
        tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_SET, &autoconnect);
    }
    // timer
    tls_os_timer_create(&KeyScanTimer, KeyScanTimerProc, NULL, KEY_SCAN_TIME, TRUE, NULL);
    tls_os_timer_start(KeyScanTimer);
    // create static user task
    CreateUserTask();
}
/***************************************************************************
* Description: ����ɨ�账��
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static void KeyScanTimerProc(void)
{
    INT16U KeyValue;

    tls_gpio_cfg(KEY_IO_ONESHOT, TLS_GPIO_DIR_INPUT, TLS_GPIO_ATTR_PULLLOW);
    gsKeyStatus = tls_gpio_read(KEY_IO_ONESHOT);
    if(gsKeyStatus)
    {
        if(gsKeyPreStatus != gsKeyStatus)
        {
            gsKeyPreStatus = gsKeyStatus;
            tls_os_queue_send(gsUserTaskQueue, (void *)MSG_ONESHOT, 0);
            printf("houxf debug oneshot key pressed \r\n");
        }
    }
    else
    {
        if(gsKeyPreStatus != gsKeyStatus)
        {
            gsKeyPreStatus = gsKeyStatus = 0;
        }
    }
}
/***************************************************************************
* Description:udp �㲥timer������
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
* Description: ����״̬�仯�ص�����
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
* Description: �����û�����
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static int CreateUserTask(void)
{
    tls_os_queue_create(&gsUserTaskQueue, &UserTaskQueue, USER_QUEUE_SIZE, 0);
    tls_os_task_create(NULL, NULL, UserTaskProc, NULL,
                    (void *)UserTaskStk,                     /* ����ջ����ʼ��ַ */
                    USER_TASK_SIZE * sizeof(u32),        /* ����ջ�Ĵ�С     */
                    USER_TASK_PRO,
                    0);
    return WM_SUCCESS;
}

/*************************************************************************** 
* Description:��ӡ����
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/ 
void ZC_TraceData1(u8* pData, u32 Len)
{
    u32 Index;
    if (0 == Len)
    {
        return;
    }
    
    ZC_Printf("++++++++++++++++++++++++++++++++++++++++++++++++\n");
    for (Index = 0; Index + 4 < Len; Index = Index + 4)
    {
        ZC_Printf("0x%02x, 0x%02x, 0x%02x, 0x%02x,\n",
            pData[Index],
            pData[Index + 1],
            pData[Index + 2],
            pData[Index + 3]);
    }
    
    for (; Index < Len - 1; Index++)
    {
        ZC_Printf("0x%02x, ", pData[Index]);
    }
    ZC_Printf("0x%02x", pData[Index]);

    ZC_Printf("\n++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

/***************************************************************************
* Description: �û�������ص�����
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static void UserTaskProc(void)
{
    void *msg;
// �����û�����
    tls_user_uart_set_baud_rate(USER_UART_BAUDRATE);
    tls_uart_cfg_user_mode();
    tls_user_uart_rx_register(UserUartRxCallback);
    // ע������״̬�ص�����
    tls_netif_add_status_event(UserWlanStatusChangedEvent);
    for(;;)
    {
        tls_os_queue_receive(gsUserTaskQueue, (void **)&msg, 0, 0);
        switch((u32)msg)
        {
            case MSG_NET_UP:                // �����ɹ�
                printf("fengq: MSG_NET_UP\n");
                HF_WakeUp();
                break;

            case MSG_NET_DOWN:              // ����Ͽ�
                printf("fengq: MSG_NET_DOWN\n");

                HF_Sleep();
                HF_BcInit();
                break;

            case MSG_ONESHOT:               // ����һ������
                printf("fengq: MSG_ONESHOT\n");
                tls_wifi_set_oneshot_flag(1);
                break;

            case MSG_SK_CLIENT_ERR:         // socket �Ͽ�
                tls_os_time_delay(200);
//                printf("fengq: MSG_SK_CLIENT_ERR\n");

                break;

            case MSG_SK_CLIENT_RX_DATA: // socket client �յ����ݿͻ������Լ�������
                break;

            case MSG_SK_SERVER_ERR:         // socket �Ͽ�
//                printf("fengq: MSG_SK_SERVER_ERR\n");
                break;

            case MSG_SK_SERVER_RX_DATA: // socket client �յ����ݿͻ������Լ�������
                break;

            case MSG_TIMER:
                break;
            case MSG_UART_RX_DATA:
			uart_proc_data();
							 // ZC_TraceData1((u8 *)msg,len);
	             // ZC_Moudlefunc((u8 *)msg,len);
			break;
            default:
                break;
        }
    }
}
/***************************************************************************
* Description: udp �㲥������������
*
* Auth: houxf
*
*Date: 2015-3-31
****************************************************************************/
static void StdUdpBroadCast(INT8U *buff, INT16U len)
{
    struct sockaddr_in pin;
    int idx;
    int socket_num;

    memset(&pin, 0, sizeof(struct sockaddr));
    pin.sin_family = AF_INET;                           //AF_INET��ʾʹ��IPv4
    pin.sin_addr.s_addr = htonl(0xffffffffUL);      //IPADDR_BROADCAST
    pin.sin_port = htons(UDP_BROAD_PORT);
    socket_num = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    for(idx = 0; idx < 3; idx++)
    {
        sendto(socket_num, buff, len, 0, (struct sockaddr *)&pin, sizeof(struct sockaddr));
        tls_os_time_delay(10);
    }
    closesocket(socket_num);
}
/*************************************************************************** 
* Description:���ڽ��ջص�����
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

