#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include "wm_type_def.h"
#include "wm_sockets.h"
#include <time.h> /* for time() and ctime() */
#include "wm_config.h"
#include "wm_debug.h"

#if TLS_CONFIG_NTP
#define UTC_NTP 2208988800U /* 1970 - 1900 ;年 换算成秒*/
#define BUF_LEN	48

#define NTP_SERVER_MAX_NUM	4
#define NTP_SERVER_IP_LEN	16
u8 serverno = NTP_SERVER_MAX_NUM;
char serverip[NTP_SERVER_MAX_NUM][NTP_SERVER_IP_LEN] = { {"218.75.4.130"},{"133.100.11.8"},{"129.6.15.28"},{"132.163.4.103"}};
/* get Timestamp for NTP in LOCAL ENDIAN */
void get_time64(uint32 *ts)
{
#if TLS_OS_FREERTOS
	ts[0] = time(NULL) + UTC_NTP;
	ts[1] = 0;
#elif TLS_OS_UCOS	//ucos 下keil 编译time函数死机
	ts[0] = UTC_NTP;
	ts[1] = 0;
#endif
}


int open_connect(unsigned char *buf)
{
	int s;

	struct sockaddr_in pin;
	u32_t ip = 0;
	uint32 tts[2]; /* Transmit Timestamp */
	int ret = 0;
	//int i;
	int servernum;
	fd_set readfd ;
	struct timeval timeout ;
	socklen_t addrlen = sizeof(struct sockaddr);

	s = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if(s < 0)
	{
		TLS_DBGPRT_ERR("sock err\n");
		return WM_FAILED;
	}
	for(servernum = 0;servernum < serverno;servernum ++ )
	{
		ip = ipaddr_addr(serverip[servernum]);
		memset(&pin, 0, sizeof(struct sockaddr));
		pin.sin_family=AF_INET;                 //AF_INET表示使用IPv4
		pin.sin_addr.s_addr=ip;  //IPADDR_udp
		pin.sin_port=htons(123);

		buf[0] = 0x23;
		get_time64(tts);
		(*(uint32 *)&buf[40]) = htonl(tts[0]);
		(*(uint32 *)&buf[44])= htonl(tts[1]);
#if 0	
		for(i = 40;i < 48;i ++)
		{
			printf("[%x]",buf[i]);
		}
		printf("\n");
#endif	
		ret = sendto(s, buf, BUF_LEN, 0, (struct sockaddr *)&pin, addrlen);
		if(ret < 0)
		{
			TLS_DBGPRT_ERR("\nsend err\n");
			closesocket(s);
			return WM_FAILED;
		}

		FD_ZERO(&readfd);
		FD_SET(s,&readfd);
		timeout.tv_sec = 5;
		timeout.tv_usec =  0;

		ret = select(s + 1 , &readfd , NULL,NULL ,&timeout) ;
		if(ret < 0)
		{
			TLS_DBGPRT_ERR("Falt to select  or timeout ");
			continue;
		}

		if(ret == 0)
		{
			TLS_DBGPRT_ERR("ip:[%s] -time out .\n",serverip[servernum]);
			continue;
		}
		
		memset(buf,0,BUF_LEN);
		ret = recvfrom(s ,buf,BUF_LEN,0,(struct sockaddr *)&pin,&addrlen);
		if(ret <=  0)
		{
			TLS_DBGPRT_ERR("Fail to recvfrom ");
			continue;
		}
		closesocket(s);
		return WM_SUCCESS;
#if 0	
		for(i = 0;i < BUF_LEN;i ++)
		{
			printf("[%x]",buf[i]);
			if(23 == i)
				printf("\n");
		}
		printf("\n");
#endif	
	}
	closesocket(s);
	return WM_FAILED;
}

int get_reply(unsigned char *buf,unsigned int *time)
{
	uint32 *pt;
#if 0	
	uint32 t1[2]; /* t1 = Originate Timestamp  */
	uint32 t2[2]; /* t2 = Receive Timestamp @ Server */
#endif	
	uint32 t3[2]; /* t3 = Transmit Timestamp @ Server */
	uint32 t4[2]; /* t4 = Receive Timestamp @ Client */
#if 0	
	double T1, T2, T3, T4;
	double tfrac = 4294967296.0;
	time_t curr_time;
	time_t diff_sec;
	struct tm *tblock;
#endif	
#if 0
	int i;
	
	for(i = 0;i < BUF_LEN;i ++)
	{
		printf("[%x]",buf[i]);
		if(23 == i)
			printf("\n");
	}
	printf("\n");
#endif
	get_time64(t4);
//	printf("%x  %x\n",t4[0],t4[1]);
#if 0	
	pt = (uint32 *)&buf[24];
	t1[0] = htonl(*pt);
	pt = (uint32 *)&buf[28];
	t1[1] = htonl(*pt);
	pt = (uint32 *)&buf[32];
	t2[0] = htonl(*pt);
	pt = (uint32 *)&buf[36];
	t2[1] = htonl(*pt);
#endif	
	pt = (uint32 *)&buf[40];
	t3[0] = htonl(*pt);
	pt = (uint32 *)&buf[44];
	t3[1] = htonl(*pt);

#if 0	//计算误差，误差太小，不用考虑
	T1 = t1[0] + t1[1]/tfrac;
	T2 = t2[0] + t2[1]/tfrac;
	T3 = t3[0] + t3[1]/tfrac;
	T4 = t4[0] + t4[1]/tfrac;

	printf( "\ndelay = %lf\n"
		"offset = %lf\n\n",
		(T4-T1) - (T3-T2),
		((T2 - T1) + (T3 - T4)) /2
	      );
#endif
	t3[0] -= UTC_NTP;
	t3[0] += 28800;	//加8小时
	//printf("server Time :   %s\n", ctime(&t3[0]));
	*time = t3[0];
#if 0
	tblock=localtime(&t3[0]);
	printf("00 sec=%d,min=%d,hour=%d,mon=%d,year=%d\n",tblock->tm_sec,tblock->tm_min,tblock->tm_hour,tblock->tm_mon,tblock->tm_year);

	printf("\n00 time=%s\n",asctime(tblock));
#endif	
	return WM_SUCCESS;
}

unsigned int ntp_client(void)
{
	int ret = 0;
	unsigned int time = 0;
	unsigned char buf[BUF_LEN] = {0};

	ret = open_connect(buf);
	if(WM_SUCCESS == ret)
	{
		get_reply(buf,&time);
	}
	//closesocket(fd);
	return time;
}

int tls_set_ntp_server(char *ipaddr)
{
	char *p1,*p2;
	
	if(NULL == serverip)
		return WM_FAILED;

	serverno = 0;
	p1 = ipaddr;	
	while(1)
	{
		p2 = strchr(p1, ';');
		if(NULL == p2)
		{			
			memcpy(serverip[serverno], p1, NTP_SERVER_IP_LEN);
			serverno ++;
			break;
		}
		memcpy(serverip[serverno], p1, p2 - p1);
		serverno ++;
		if(serverno >= NTP_SERVER_MAX_NUM)
			break;
		p1 = p2 + 1;			
	}
{
	int i;
	for(i = 0;i < serverno;i ++)
	{
		printf("server[%d]=[%s]\n",i,serverip[i]);
	}
}
	return WM_SUCCESS;
}

#endif



