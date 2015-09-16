#ifndef __WM_DEMO_H__
#define __WM_DEMO_H__

#define DEMO_ON		1
#define DEMO_OFF		0

//demo 控制台，演示demo的时候必须打开该项
#define DEMO_CONSOLE				DEMO_OFF

//socket demo，分为raw接口和标准接口,下面的5个宏可以同时打开，
//演示的时候，演示完一个socket demo，模块需要复位才能演示下一个socket demo
#define DEMO_RAW_SOCKET_CLIENT	(DEMO_OFF && TLS_CONFIG_SOCKET_RAW) 	//raw 接口socket client
#define DEMO_RAW_SOCKET_SERVER	(DEMO_OFF && TLS_CONFIG_SOCKET_RAW) 	//raw 接口socket server
#define DEMO_STD_SOCKET_CLIENT	(DEMO_OFF && TLS_CONFIG_SOCKET_STD)	//标准接口socket client
#define DEMO_STD_SOCKET_SERVER	(DEMO_OFF && TLS_CONFIG_SOCKET_STD)	//标准接口socket server
#define DEMO_STD_SOCKET_SER_SEL    (DEMO_OFF && TLS_CONFIG_SOCKET_STD)    //标准接口socket server, select 方式

//联网demo，可以用一键配置联网，也可以主动用接口联网
#define DEMO_CONNECT_NET			DEMO_OFF

//apsta联网demo，可以用一键配置联网，也可以主动用接口联网
#define DEMO_APSTA   		  		(DEMO_OFF && TLS_CONFIG_APSTA)

//多播广播demo
#define DEMO_UDP_MULTI_CAST        	(DEMO_OFF && TLS_CONFIG_SOCKET_STD && TLS_CONFIG_IGMP) 

//socket 升级demo
#define DEMO_SOCKET_FWUP      		(DEMO_OFF && TLS_CONFIG_SOCKET_RAW)

//AP dmeo
#define DEMO_SOFT_AP   		  		(DEMO_OFF && TLS_CONFIG_AP)

//WPS demo	
#define DEMO_WPS			  		(DEMO_OFF && TLS_CONFIG_WPS && TLS_IEEE8021X_EAPOL)

//http demo
#define DEMO_HTTP					(DEMO_OFF && TLS_CONFIG_HTTP_CLIENT)

//http parse xml demo
#define DEMO_HTTP_XML_PARSE           (DEMO_OFF && DEMO_HTTP)

//http parse small xml demo
#define DEMO_HTTP_SXML_PARSE         (DEMO_OFF && DEMO_HTTP)

//http parse json demo
#define DEMO_HTTP_JSON_PARSE         (DEMO_OFF && DEMO_HTTP)

//gpio demo
#define DEMO_GPIO					DEMO_OFF

//flash demo
#define DEMO_FLASH					DEMO_OFF

//master spi demo
#define DEMO_MASTER_SPI			DEMO_OFF

//slave spi demo
#define DEMO_SLAVE_SPI				(DEMO_OFF && TLS_CONFIG_HS_SPI)

//加解密demo
#define DEMO_ENCRYPT				DEMO_OFF

//i2c demo
#define DEMO_I2C					DEMO_OFF

//adc demo
#define DEMO_ADC					DEMO_OFF

//pwm demo
#define DEMO_PWM					DEMO_OFF

#define DEMO_DLNA_DMR				DEMO_OFF

//cloud demo
#define DEMO_CLOUD					(DEMO_OFF && TLS_CONFIG_CLOUD)

//ntp demo
#define DEMO_NTP					(DEMO_OFF && TLS_CONFIG_NTP)

//alljoyn led demo
#define DEMO_ALLJOYN_LED                     (DEMO_OFF && TLS_CONFIG_SOCKET_STD)

//kii cloud demo
#define DEMO_KII				       (DEMO_OFF && TLS_CONFIG_CLOUD_KII)

////////////////////////////////////////////////////////////////

#define RemotePort	1000	//demo作为client时，远程端口
#define LocalPort		1020	//demo作为server时，本地端口


// user prio 32 - 60
#define DEMO_TASK_PRIO			32
#define  DEMO_RAW_SOCKET_C_TASK_PRIO	(DEMO_TASK_PRIO + 1)
#define  DEMO_RAW_SOCKET_S_TASK_PRIO	(DEMO_RAW_SOCKET_C_TASK_PRIO + 1)
#define  DEMO_SOCKET_C_TASK_PRIO	(DEMO_RAW_SOCKET_S_TASK_PRIO + 1)
#define  DEMO_SOCKET_S_TASK_PRIO	(DEMO_SOCKET_C_TASK_PRIO + 1)
#define  DEMO_SOCKET_RECEIVE_TASK_PRIO	(DEMO_SOCKET_S_TASK_PRIO + 1)
#define  DEMO_MCAST_TASK_PRIO	(DEMO_SOCKET_RECEIVE_TASK_PRIO + 1)
#define  DEMO_SOCK_FWUP_TASK_PRIO	(DEMO_MCAST_TASK_PRIO + 1)
#define  DEMO_SOCK_S_SEL_TASK_PRIO	(DEMO_SOCK_FWUP_TASK_PRIO + 1)
#define  DEMO_ONESHOT_TASK_PRIO	(DEMO_SOCK_S_SEL_TASK_PRIO + 1)
#define  DEMO_DMR_TASK_PRIO	(DEMO_ONESHOT_TASK_PRIO + 1)
#define  DEMO_CLOUD_TASK_PRIO (DEMO_DMR_TASK_PRIO + 1)
#define  DEMO_ALLJOYN_LED_TASK_PRIO (DEMO_CLOUD_TASK_PRIO + 1)
#define  DEMO_KII_PUSH_RECV_MSG_TASK_PRIO	(DEMO_ALLJOYN_LED_TASK_PRIO + 1)
#define  DEMO_KII_PUSH_PINGREQ_TASK_PRIO	(DEMO_KII_PUSH_RECV_MSG_TASK_PRIO + 1)

#define DEMO_QUEUE_SIZE	32

#define DEMO_BUF_SIZE		TLS_UART_RX_BUF_SIZE

#define DEMO_CONSOLE_CMD			1		//被解析成cmd
#define DEMO_CONSOLE_SHORT_CMD	2		//CMD的一部分，没有解析完

/*定义demo中可能用到的消息*/
#define	DEMO_MSG_WJOIN_FAILD	1
#define	DEMO_MSG_WJOIN_SUCCESS	2
#define DEMO_MSG_SOCKET_RECEIVE_DATA		3
#define	DEMO_MSG_UART_RECEIVE_DATA			4
#define	DEMO_MSG_SOCKET_ERR					5
#define DEMO_MSG_SOCKET_CREATE				6
#define DEMO_MSG_SOCKET_TEST				7
#define DEMO_MSG_OPEN_UART					8


typedef struct demo_sys{
	char *rxbuf;		/*uart rx*/
	char *txbuf;		/*uart tx*/
	u16 wptr;
	u16 rptr;
	u8 overflag;		/*溢出标志*/
	u8 MsgNum;


	bool socket_ok;
	int socket_num;
	char *sock_rx;
	u16 sock_data_len;

	int recvlen;		//socket接收的数据长度，用于测试
	int translen;		//socket发送的数据长度，用于测试
	u8 is_raw; // 1:raw socket; 0:标准socket
}ST_Demo_Sys;

struct demo_console_info_t {
    char *cmd;
    int (*callfn)(char *buf);	
    char *info;
};

void CreateDemoTask(void);
void DemoStdSockOneshotSendMac(void);
void DemoRawSockOneshotSendMac(void);


#endif
