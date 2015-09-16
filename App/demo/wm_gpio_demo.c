/***************************************************************************** 
* 
* File Name : wm_gpio_demo.c 
* 
* Description: gpio demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-2 
*****************************************************************************/ 
#include "wm_include.h"

#if DEMO_GPIO

#define DEMO_ISR_IO		12
void demo_gpio_isr_callback(void *context)
{
	u16 ret;

	
	ret = tls_get_gpio_int_flag(DEMO_ISR_IO);
	printf("\nint flag =%d\n",ret);
	if(ret)
	{
		tls_clr_gpio_int_flag(DEMO_ISR_IO);
		ret = tls_gpio_read(DEMO_ISR_IO);
		printf("\nafter int io =%d\n",ret);
	}
}

//gpio ≤‚ ‘≥Ã–Ú
int gpio_demo(char *buf)
{
	u16 gpio_pin;
	u16 ret;
	
	//≤‚ ‘gpio 11,12,13
	for(gpio_pin = 11; gpio_pin < 14; gpio_pin ++)
	{
		tls_gpio_cfg(gpio_pin, TLS_GPIO_DIR_INPUT, TLS_GPIO_ATTR_FLOATING);
		ret = tls_gpio_read(gpio_pin);	/*œ»∂¡ƒ¨»œ◊¥Ã¨*/
		printf("\ngpio[%d] default value==[%d]\n",gpio_pin,ret);
		
		tls_gpio_cfg(gpio_pin, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_FLOATING);
		tls_gpio_write(gpio_pin,1);			/*–¥∏ﬂ*/
		ret = tls_gpio_read(gpio_pin);	
		printf("\ngpio[%d] floating high value==[%d]\n",gpio_pin,ret);

		tls_gpio_cfg(gpio_pin, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_FLOATING);
		tls_gpio_write(gpio_pin,0);			/*–¥µÕ*/
		ret = tls_gpio_read(gpio_pin);	
		printf("\ngpio[%d] floating low value==[%d]\n",gpio_pin,ret);

		tls_gpio_cfg(gpio_pin, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_PULLLOW);
		tls_gpio_write(gpio_pin,1);			/*–¥∏ﬂ*/
		ret = tls_gpio_read(gpio_pin);	
		printf("\ngpio[%d] pulllow high value==[%d]\n",gpio_pin,ret);

		tls_gpio_cfg(gpio_pin, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_PULLLOW);
		tls_gpio_write(gpio_pin,0);			/*–¥µÕ*/
		ret = tls_gpio_read(gpio_pin);	
		printf("\ngpio[%d] pulllow low value==[%d]\n",gpio_pin,ret);
		
	}

	return WM_SUCCESS;
}


int gpio_isr_test(char *buf)
{
	u16 gpio_pin;
	
	gpio_pin = DEMO_ISR_IO;

	//≤‚ ‘÷–∂œ
	tls_gpio_cfg(gpio_pin, TLS_GPIO_DIR_INPUT, TLS_GPIO_ATTR_PULLLOW);
	tls_gpio_isr_register(demo_gpio_isr_callback,NULL);
	tls_gpio_int_enable(gpio_pin, TLS_GPIO_INT_TRIG_RISING_EDGE);
	printf("\ntest gpio %d rising isr\n",gpio_pin);
	return WM_SUCCESS;
}

#endif
