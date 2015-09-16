/***************************************************************************** 
* 
* File Name : wm_slave_spi_demo.c 
* 
* Description: SPI slave demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-11
*****************************************************************************/ 

#include "wm_include.h"

#if DEMO_SLAVE_SPI
#if (TLS_CONFIG_HOSTIF && TLS_CONFIG_HS_SPI)
void testhspirxdata(char *buf)
{
	int i;
	printf("\nrx data addr=%x\n",buf);
	for(i = 0;i < 32;i ++)
	{
		printf("[%x]",buf[i]);
		if(0 == i%10)
			printf("\n");
	}

	tls_hspi_tx_data("\ndata received \n", 16);/*这里仅仅是测试，告诉主机数据收到*/
}

void testhspirxcmd(char *buf)
{
	int i;

	for(i = 0;i < 32;i ++)
	{
		 printf("[%x]",buf[i]);
		 if(0 == i%10)
			printf("\n");
	}

	tls_hspi_tx_data("\ncmd received  \n", 16);/*这里仅仅是测试，告诉主机命令收到*/
}

//注意 :该demo 不可以在user uart中输入命令测试，
//因为user uart 和slave spi接口共用，会有冲突，
//所以需要自己在demo任务中调用该函数即可
void slave_spi_demo(void)
{
	tls_slave_spi_init(HSPI_INTERFACE_SPI);	//或者改成HSPI_INTERFACE_SDIO
	tls_set_hspi_user_mode(1);
	/*注册函数需要放在tls_set_hspi_user_mode之后*/
	tls_hspi_rx_cmd_register(testhspirxcmd);
	tls_hspi_rx_data_register(testhspirxdata);
	tls_hspi_tx_data_register(NULL);
}
#endif
#endif
