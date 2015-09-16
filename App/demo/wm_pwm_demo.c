/***************************************************************************** 
* 
* File Name : wm_pwm_demo.c 
* 
* Description: pwm demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-7-18 
*****************************************************************************/ 
#include <string.h>
#include "wm_include.h"
#include "wm_pwm.h"

#if DEMO_PWM
extern const char DEMO_PWM_SET[];

int pwm_demo(char *buf)
{
	u16 freq[5] = {400,300,200,100,0};
	u8 duty[5] = {50,50,50,50,0};
	tls_pwm_init(3, freq, duty);
	//pwm_loop_duty();
	return WM_SUCCESS;
}

int pwm_loop_duty(void)
{
	int duty = 0;

	while(1)
	{
		for(duty = 0;duty < PWM_DEPTH;duty += 3)
		{
			tls_pwm_duty_set(0,duty);
			tls_os_time_delay(3);
		}

		for(duty = PWM_DEPTH;duty >= 0;duty -= 3)
		{
			tls_pwm_duty_set(0,duty);
			tls_os_time_delay(3);
		}
	}
}

int pwm_demo_freq_duty_set(char *buf)
{
	char *p,*p1;
	u16 freq = 0;
	u16 duty = 0;
	int i = 0;

	if(NULL == strchr(buf,';'))
	{
		return DEMO_CONSOLE_SHORT_CMD;
	}
	p1 = strstr(buf,DEMO_PWM_SET);
	if(NULL == p1)
		return WM_FAILED;
	p1 += strlen(DEMO_PWM_SET);
	while(1)
	{
		p = strchr(p1,'(');
		if(p == NULL)
		{
			return WM_FAILED;
		}

		p1 = p + 1;
		p = strchr(p1,',');
		if(p != NULL)
		{
			*p = 0;
			p ++;
		}
		else
		{
			return	WM_FAILED;
		}
		freq = atoi(p1);
		printf("\nfreq==%d\n",freq);
		tls_pwm_freq_set(i,freq);
		p1 = strchr(p,')');
		if(p1 == NULL)
		{
			return 	WM_FAILED;
		}
		*p1 = 0;
		p1 ++;
		duty = atoi(p);
		printf("\nduty ==%d\n",duty);

		tls_pwm_duty_set(i,duty);		
		i ++;
	}	

}
#endif

