/***************************************************************************** 
* 
* File Name : wm_ntp_demo.c 
* 
* Description: ntp demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-10-22 
*****************************************************************************/ 
#include "wm_include.h"
#include <string.h>
#include <time.h>
#include "wm_rtc.h"
#include "wm_ntp.h"

#if DEMO_NTP
extern const char DEMO_SET_NTP_S[];

int ntp_demo(char *buf)
{
	unsigned int t;	//日历时间相对时间，1970到现在的相对时间
	struct tm *tblock;
#if 0	
	struct tm tb2;
#endif	
	printf("\nntp demo\n");
	t = ntp_client();

	printf("now Time :   %s\n", ctime(&t));
	tblock=localtime(&t);	//把日历时间转换成本地时间，已经加上与世界时间8小时的偏差,以1900为基准
	//printf(" sec=%d,min=%d,hour=%d,mon=%d,year=%d\n",tblock->tm_sec,tblock->tm_min,tblock->tm_hour,tblock->tm_mon,tblock->tm_year);
	tls_set_rtc(tblock);
#if 0	
	tls_os_time_delay(1000);
	memset(&tb2,0,sizeof(struct tm));
	tls_get_rtc(&tb2);
	tb2.tm_wday = tblock->tm_wday;
	printf("\ntime=%s\n",asctime(&tb2));
#endif	
	return WM_SUCCESS;
}


int ntp_set_server_demo(char *buf)
{
	char *p;
	
	p = strstr(buf,DEMO_SET_NTP_S);
	if(NULL == p)
		return WM_FAILED;
	p = strchr(buf,')');
	if(NULL == p)
	{
		return DEMO_CONSOLE_SHORT_CMD;
	}
	*p = 0;
	
	tls_set_ntp_server(buf + strlen(DEMO_SET_NTP_S) + 2);

	return WM_SUCCESS;

}

#endif
