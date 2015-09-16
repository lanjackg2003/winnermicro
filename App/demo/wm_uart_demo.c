/***************************************************************************** 
* 
* File Name : wm_uart_demo.c 
* 
* Description: uart demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-2 
*****************************************************************************/ 
#include <string.h>
#include "wm_include.h"
#include "wm_http_fwup.h"
#include "wm_sockets.h"
#include "wm_cpu.h"

#if DEMO_CONSOLE
  
int uartrxlen = 0;
extern int opentx;
extern ST_Demo_Sys gDemoSys;
extern tls_os_queue_t *demo_q;
extern u8 RemoteIp[4];
extern int gpio_demo(char *buf);
extern int gpio_isr_test(char *buf);
extern int flash_demo(char *buf);
extern int spi_demo(char *buf);
extern int crypt_demo(char *buf);
extern int http_fwup_demo(char *buf);
extern int http_get_demo(char *buf);
extern int http_post_demo(char* postData);
extern int http_put_demo(char* putData);
#if DEMO_HTTP_XML_PARSE || DEMO_HTTP_SXML_PARSE
extern int http_parse_xml(char *buf);
#endif
#if DEMO_HTTP_JSON_PARSE
extern int http_parse_json(char *buf);
#endif
extern int CreateRawSockClientDemoTask(char *buf);
extern int CreateRawSockServerDemoTask(char *buf);
extern int CreateSockClientDemoTask(char *buf);
extern int CreateSockServerDemoTask(char *buf);
extern int CreateSockSSelDemoTask(char *buf);
extern int soft_ap_demo(char *buf);
extern int apsta_demo(char *buf);
extern int demo_wps_pbc(char *buf);
extern int demo_wps_pin(char *buf);
extern int demo_wps_get_pin(char *buf);
extern int CreateHttpDemoTask(char *buf);
extern int CreateMCastDemoTask(char *buf);
extern int CreateSockFwupDemoTask(char *buf);
extern int kiiDemo_test(char *buf);
int demo_console_show_help(char *buf);
static int demo_modify_baudrate(char *buf);
static int demo_clear_test_len(char *buf);
static int demo_show_test_len(char *buf);
static int demo_change_tx_status(char *buf);
static int demo_clear_oneshot_flag(char *buf);
static int demo_close_uart(char *buf);
#if (DEMO_RAW_SOCKET_CLIENT||DEMO_STD_SOCKET_CLIENT||DEMO_HTTP)
static int demo_set_remote_ip(char *buf);
#endif
extern int DemoConnectNet(char *buf);
static int demo_reset_sys(char *buf);
extern int i2c_demo(char *buf);
extern int pwm_demo(char *buf);
extern int adc_demo(char *buf);
extern int pwm_demo_freq_duty_set(char *buf);
extern int ntp_demo(char *buf);
extern int ntp_set_server_demo(char *buf);
#if DEMO_DLNA_DMR
extern int CreateMediaRender(char *buf);
#endif
extern int CraeteCloudDemoTask(void);
#if DEMO_ALLJOYN_LED
extern int tls_start_alljoyn_led_demo(char *buf);
#endif

//下面定义的字符串会使用一次以上
const char REMOTE_IP[] = "remoteip";
const char LAST_CMD[] = "lastcmd";
const char HTTP_POST[] = "t-httppost";
const char HTTP_PUT[] = "t-httpput";
const char DEMO_HELP[] ="demohelp";
const char DEMO_ONESHOT[] = "t-oneshot";
const char DEMO_CONNET[] = "t-connect";
const char DEMO_PWM_SET[] = "t-setpwm";
const char DEMO_SET_NTP_S[] = "t-setntps";
	
static struct demo_console_info_t  console_tbl[] = 
{
#if DEMO_GPIO
	{"t-gpio", 	gpio_demo,					"Test Read/Write GPIO "},
	{"t-ioisr", 	gpio_isr_test,				"Test GPIO's interrupt"},
#endif
#if DEMO_I2C
	{"t-i2c", 		i2c_demo,					"Test I2C"},
#endif
#if DEMO_PWM
	{"t-pwm",	pwm_demo,					"Test pwm"},
	{(char *)DEMO_PWM_SET, pwm_demo_freq_duty_set,	"Set PWM freq and duty,for example:t-setpwm=(200,50),(300,70),(160,150),(180,30);"}, 
#endif
#if DEMO_ADC
	{"t-adc",		adc_demo,					"Test adc"},
#endif
#if DEMO_FLASH
	{"t-flash", 	flash_demo,					"Test Read/Write Flash "},
#endif
#if DEMO_MASTER_SPI
	{"t-mspi", 	spi_demo,					"Test SPI Master function(Note: need another module support as a client device)"},
#endif
#if DEMO_ENCRYPT
	{"t-crypt", 	crypt_demo,					"Test Encryption/Decryption API"},
#endif
#if DEMO_CONNECT_NET
	{(char *)DEMO_ONESHOT, 	DemoConnectNet,"Test connecting with AP via one_shot_configure function"},
	{(char *)DEMO_CONNET, 	DemoConnectNet,"Test connecting with AP via API; For example, t-connect(\"ssid\",\"pwd\"); For OPEN encrypt type, pwd SHOULD be empty string"},
#endif
#if DEMO_WPS
	{"t-wpspbc", 	demo_wps_pbc,				"Test connecting with AP via WPS PBC method"},
	{"t-wpspin", 	demo_wps_pin,				"Test connecting with AP via WPS PIN method, (Note: need run \"t-wpsgetpin\" to get pin code in advance)"},
	{"t-wpsgetpin", demo_wps_get_pin,			"Test generating random WPS PIN code"},
#endif	
#if DEMO_UDP_MULTI_CAST
	{"t-mcast",	CreateMCastDemoTask,		"Test Multicast & Broadcast data stream"},
#endif
#if DEMO_SOCKET_FWUP
	{"t-skfwup", 	CreateSockFwupDemoTask,	"Test Firmware updating via cellphone(Note: firmware working as socket server)"},
#endif
#if DEMO_RAW_SOCKET_CLIENT
	{"t-rawskc", 	CreateRawSockClientDemoTask, "Test data stream as [RAW SOCKET] CLIENT(working after connecting with AP successfully)"},
#endif
#if DEMO_RAW_SOCKET_SERVER
	{"t-rawsks", 	CreateRawSockServerDemoTask,"Test data stream as [RAW SOCKET] SERVER(working after connecting with AP successfully)"},
#endif
#if DEMO_STD_SOCKET_CLIENT
	{"t-stdskc", 	CreateSockClientDemoTask,	"Test data stream as [STANDARD SOCKET] CLIENT(working after connecting with AP successfully)"},
#endif
#if DEMO_STD_SOCKET_SERVER
	{"t-stdsks", 	CreateSockServerDemoTask,	"Test data stream as [STANDARD SOCKET] SERVER(working after connecting with AP successfully)"},
#endif
#if DEMO_STD_SOCKET_SER_SEL
	{"t-stdsocks", 	CreateSockSSelDemoTask,	"Test number of sockets supported currently(Maximum Seven clients can be created; one used in this demo for server)"},
#endif
#if DEMO_SOFT_AP
	{"t-softap", 	soft_ap_demo,				"Test Creating SoftAP"},
#endif
#if DEMO_APSTA
	{"t-apsta", 	apsta_demo,	"Test connecting with AP via API; For example, t-apsta(\"ssid\",\"pwd\", \"apstassid\")"},
#endif
#if DEMO_HTTP
	{"t-httpfwup", http_fwup_demo,			"Test firmware update via HTTP"},
	{"t-httpget", 	http_get_demo,				"Test HTTP Download"},
	{(char *)HTTP_POST, http_post_demo,		"Test HTTP Upload"},
	{(char *)HTTP_PUT, http_put_demo,		"Test HTTP Put method"},
#if DEMO_HTTP_XML_PARSE || DEMO_HTTP_SXML_PARSE
	{"t-httpparsexml",    http_parse_xml,		"Test HTTP Download xml data and parse it"},
#endif //DEMO_HTTP_XML_PARSE
#if DEMO_HTTP_JSON_PARSE
	{"t-httpparsejson",    http_parse_json,		"Test HTTP Download json data and parse it"},
#endif //DEMO_HTTP_JSON_PARSE
#endif //DEMO_HTTP
#if DEMO_DLNA_DMR
	{"t-dlnadmr",    CreateMediaRender,		"Test DLNA DMR"},
#endif
#if DEMO_CLOUD
	{"t-jdcloud",	CraeteCloudDemoTask,	"Test JD Cloud Function"},
#endif
#if DEMO_NTP
	{(char *)DEMO_SET_NTP_S,    ntp_set_server_demo,		"Set NTP server ip;For example:t-setntps=(192.168.1.100;192.168.1.101),max server num is four"},
	{"t-ntp",    ntp_demo,		"Test NTP"},
#endif
#if DEMO_ALLJOYN_LED
	{"t-alljoynled",    tls_start_alljoyn_led_demo,		"Test Alljoyn LED"},
#endif
#if (DEMO_RAW_SOCKET_CLIENT||DEMO_STD_SOCKET_CLIENT||DEMO_HTTP)
	{(char *)REMOTE_IP, demo_set_remote_ip,	"Set remoteIP parameter (the server IP address for these Demos); For example,remoteip=192.168.1.112"},
#endif	
#if DEMO_KII
	{"t-kii", kiiDemo_test, "Kii demo test"},
#endif	
	{"baudrate", 	demo_modify_baudrate,		"Set baudrate of UART for this console; For example,baudrate=115200;"},
	{"closeuart", 	demo_close_uart,				"Close this console"},
	//控制台上显示的最后一个命令，如果要让命令显示在控制台上，需要放在该行的上面
	{(char *)DEMO_HELP, 	demo_console_show_help,		"Display Help information"},
	//下面的命令用于内部测试，不显示在控制台上
	{"clearlen", 	demo_clear_test_len,			"Cleanup \"Data length\" received/sent from socket "},
	{"showlen", 	demo_show_test_len,			"Display \"Data length\" received/sent from socket"},
	{"opentx", 	demo_change_tx_status,		"SWITCH for whether displaying the Data received from socket on console"},
	{"clearoneshot", 	demo_clear_oneshot_flag,	"Cleanup WinnerMicro OneShot Config Flag"},
	{"reset", demo_reset_sys, "Reset System"},
//最后一个命令，检索命令时判断结束标识
	{(char *)LAST_CMD, 	NULL,				"Table Terminal Flag; MUST BE THE LAST ONE"}
};

void demo_uart_malloc(void)
{
	gDemoSys.txbuf = tls_mem_alloc(DEMO_BUF_SIZE);
	if(NULL == gDemoSys.txbuf)
	{
		printf("\nmalloc tx fail\n");
		return;
	}
	memset(gDemoSys.txbuf, 0, DEMO_BUF_SIZE);

	gDemoSys.rxbuf = tls_mem_alloc(DEMO_BUF_SIZE);
	if(NULL == gDemoSys.rxbuf)
	{
		printf("\nmalloc rx fail\n");
		tls_mem_free(gDemoSys.txbuf);
		return;
	}
	memset(gDemoSys.rxbuf, 0, DEMO_BUF_SIZE);		
}

void demo_uart_free(void)
{
	if(gDemoSys.txbuf)
	{
		tls_mem_free(gDemoSys.txbuf);
		gDemoSys.txbuf = NULL;
	}

	if(gDemoSys.rxbuf)
	{
		tls_mem_free(gDemoSys.rxbuf);
		gDemoSys.rxbuf = NULL;
	}
}


s16 demo_uart_rx(char *buf, u16 len)
{
	u16 temp;
	u16 size;
	u16 wcount;
	
	uartrxlen+= len;

	if(gDemoSys.wptr > gDemoSys.rptr)
	{
		size = DEMO_BUF_SIZE - gDemoSys.wptr + gDemoSys.rptr;
	}
	else if(gDemoSys.wptr < gDemoSys.rptr)
	{
	//	printf("\nw<r\n");
		size = gDemoSys.rptr - gDemoSys.wptr;
	}
	else if(gDemoSys.wptr == gDemoSys.rptr)
	{
		if(gDemoSys.overflag)
		{
			printf("\nover buf\n");
			size = 0;
			if(gDemoSys.MsgNum < 1)
			{
				tls_os_queue_send(demo_q,(void *)DEMO_MSG_UART_RECEIVE_DATA,0);
				gDemoSys.MsgNum ++;
			}
			return -1;
		}
		else
		{
			size = DEMO_BUF_SIZE;
		}
	}
	if(size >= len)
	{
		wcount = len;
	}
	else
	{
		gDemoSys.overflag = 1;	/*表示数据有溢出*/
		wcount = size;
		printf("\nrx buf full\n");
	}
	

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
	return 0;
}

  
void demo_uart_open(void)
{	
#if TLS_CONFIG_UART
	tls_uart_cfg_user_mode();
	tls_user_uart_rx_register( demo_uart_rx);
#endif	
	gDemoSys.overflag = 0;
	gDemoSys.MsgNum = 0;
}


static void demo_console_show_info(char *buf)
{
	char *p = NULL;
	char *p1 = NULL;	

	p = buf;
	p1 = strchr(p, '\n');
	if(NULL == p1)
	{
		printf("%s\n",p);
		return;
	}
	
	while(p1 != NULL)
	{
		*p1 = '\0';
		printf("%s\n",p);
		printf("%-30s","   ");
		p = p1 + 1;
		p1 = strchr(p, '\n');
	}
	printf("%s\n",p);
}

int demo_console_show_help(char *buf)
{
	int i;
	
	printf("\n%-10s","Sequence");
	printf("%-20s","Command");
	printf("%s","Description");
	printf("\n---------------------------------------------------------------------\n");
	for(i = 0; ;i ++)
	{
		printf("%-10d",i+1);
		printf("%-20s",console_tbl[i].cmd);
		//printf("%s\n",console_tbl[i].info);
		demo_console_show_info(console_tbl[i].info);
		if(0 == strcmp(console_tbl[i].cmd,DEMO_HELP))
			break;
	}
	printf("-----------------------------------------------------------------------\n");

	return WM_SUCCESS;
}

static int demo_modify_baudrate(char *buf)
{
		u32 baudrate;
		char * p,*p1;
						//baudrate=38400; 命令示例
		p = strstr(buf,"baudrate");
		printf("\n%s\n",p);
		p1 = strchr(buf, ';');
		if(NULL == p1)
		{
			return DEMO_CONSOLE_SHORT_CMD;
		}
		*p1 = 0;
		baudrate = atoi(p + 9);
		printf("\nbaudrate=%d\n",baudrate);
#if TLS_CONFIG_UART
		tls_user_uart_set_baud_rate(baudrate);
#endif

	return WM_SUCCESS;
}

//内部测试时使用，把发送接收的数据长度清零，重新计算
static int demo_clear_test_len(char *buf)
{
	gDemoSys.recvlen = 0;
	gDemoSys.translen = 0;
	uartrxlen = 0;
#if TLS_CONFIG_UART		
{
	extern void clear_rx_len(void);

	clear_rx_len();
}
#endif	

	return WM_SUCCESS;
}

//内部测试使用，把
static int demo_show_test_len(char *buf)
{
#if TLS_CONFIG_UART	
{
	extern int get_rx_len(void);

	printf("\ndemo uartrxlen=%d,translen=%d ,uartrxlen=%d\n",uartrxlen - 9,gDemoSys.translen,get_rx_len() - 9);
}
#endif
	return WM_SUCCESS;
}

//内部测试使用，是否把socket收到的数据显示在串口上显示
static int demo_change_tx_status(char *buf)
{
	opentx = !opentx;
	printf("\nopentx=%d\n",opentx);
	return WM_SUCCESS;
}

//测试使用，清除一键配置标识
static int demo_clear_oneshot_flag(char *buf)
{
	tls_wifi_set_oneshot_flag(0);
	return WM_SUCCESS;
}

static int demo_reset_sys(char *buf){
	tls_sys_reset();
	return WM_SUCCESS;
}

static int demo_close_uart(char *buf)
{
#if TLS_CONFIG_UART
	tls_uart_disable_user_mode();
#endif
	printf("\nconsole is closed!\n");
	return WM_SUCCESS;
}

//测试使用，测试socket的client时，设置远程ip地址，用于建立socket连接
#if (DEMO_RAW_SOCKET_CLIENT||DEMO_STD_SOCKET_CLIENT||DEMO_HTTP)
static int demo_set_remote_ip(char *buf)
{
	u32_t ip = 0;
	char *param = NULL;

	if(strlen(buf) <= 17)
	{
		return DEMO_CONSOLE_SHORT_CMD;
	}
	printf("\nyour input is:%s",buf);
	param = strstr(buf,REMOTE_IP);
	if(NULL == param)
	{
		return WM_FAILED;
	}
	
	ip = ipaddr_addr(param + (strlen(REMOTE_IP)) + 1);	//+1 因为后面有个'='
	if(ip != 0)
	{
		printf("\nu32 ip=%x",ip);
		RemoteIp[0] = ip4_addr1(&ip);
		if(RemoteIp[0] > 0)
		{
			RemoteIp[1] = ip4_addr2(&ip);
			RemoteIp[2] = ip4_addr3(&ip);
			RemoteIp[3] = ip4_addr4(&ip);
			printf("\nremote ip=%d.%d.%d.%d",RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3]);
		}
	}
	return WM_SUCCESS;
}
#endif


//通过串口，模拟从pc向模块发送一些字符串命令，进行api功能的测试
//如果不是字符串命令，就认为是需要通过socket发送的数据
int demo_uart_cmd_parse(ST_Demo_Sys *sys)
{
	int ifcmd = 0;	
	int i;
	int ret;

	for(i = 0;;i ++)
	{
		if(strstr(sys->rxbuf + sys->rptr, console_tbl[i].cmd) !=NULL)
		{
			if(console_tbl[i].callfn)
			{
				ret = console_tbl[i].callfn(sys->rxbuf + sys->rptr);
				if(DEMO_CONSOLE_SHORT_CMD == ret)
					return ret;
				else
					return DEMO_CONSOLE_CMD;
			}
			else
			{
				ifcmd = DEMO_CONSOLE_CMD;
				break;
			}
		}
		if(strstr(console_tbl[i].cmd, LAST_CMD) !=NULL)	//已经到最后一个
		{
			break;
		}
	}

	return ifcmd;
}

#endif
