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

	tls_hspi_tx_data("\ndata received \n", 16);/*��������ǲ��ԣ��������������յ�*/
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

	tls_hspi_tx_data("\ncmd received  \n", 16);/*��������ǲ��ԣ��������������յ�*/
}

//ע�� :��demo ��������user uart������������ԣ�
//��Ϊuser uart ��slave spi�ӿڹ��ã����г�ͻ��
//������Ҫ�Լ���demo�����е��øú�������
void slave_spi_demo(void)
{
	tls_slave_spi_init(HSPI_INTERFACE_SPI);	//���߸ĳ�HSPI_INTERFACE_SDIO
	tls_set_hspi_user_mode(1);
	/*ע�ắ����Ҫ����tls_set_hspi_user_mode֮��*/
	tls_hspi_rx_cmd_register(testhspirxcmd);
	tls_hspi_rx_data_register(testhspirxdata);
	tls_hspi_tx_data_register(NULL);
}
#endif
#endif
