/***************************************************************************** 
* 
* File Name : wm_master_spi_demo.c 
* 
* Description: SPI master demo function 
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

#if DEMO_MASTER_SPI

#define TEST_SPI_SPEED_SIZE		2*1024
#define CS_CTRL_SOFT	1

void TestSPIReceiveData(void)
{
	u8 cmd[40];
	u8 buf[40];
	u16 temp = 0;
	u16 i;
#if 1
	memset(cmd,0,32);
	memset(buf,0,32);
	cmd[0] = 0x06;
#if 	CS_CTRL_SOFT
	tls_gpio_write(18, 0);
#endif
	tls_spi_write_then_read(cmd, 1, buf, 2);
#if 	CS_CTRL_SOFT
	tls_gpio_write(18, 1);
#endif

	printf("\nrx buf[%x][%x]\n",buf[0],buf[1]);	
#endif

	if(buf[0] & 0x01)	//数据或命令已经准备好
	{
		temp = 0;

		cmd[0] = 0x02;
#if 	CS_CTRL_SOFT
	tls_gpio_write(18, 0);
#endif		
	tls_spi_write_then_read(cmd,1,buf,2);
#if 	CS_CTRL_SOFT
	tls_gpio_write(18, 1);
#endif
		temp |= buf[0];
		temp |= buf[1] << 8;
	
		printf("\ntemp=%d\n",temp);
		if(temp > 0)
		{
			
//这里最好判断一下数据长度是否4的整数倍，留4个byte通过0x10命令接收
			cmd[0] = 0;
#if !CS_CTRL_SOFT
			
			tls_spi_write_then_read(cmd,1,buf,(temp-1)/4*4);
	 		cmd[0] = 0x10;
			tls_spi_write_then_read(cmd,1,buf + (temp-1)/4*4,temp-(temp-1)/4*4);

#else	
	//下面这段程序主要测试把写命令和读数据分成两步来做，如果不用
	//软件控制cs，写完之后cs会被拉高，读之前再拉低，则这样读出的数据
	//开始会有一个无效byte.
			tls_gpio_write(18, 0);
			tls_spi_write(cmd,1);
			
			for(i = 0;i < temp/4;i ++)
			{	
				if((i+1)*4 == temp)
					break;
				tls_spi_read(buf + i*4,4);
			}
		
			tls_gpio_write(18, 1);
			tls_gpio_write(18, 0);
			cmd[0] = 0x10;
			tls_spi_write(cmd,1);
			tls_spi_read(buf + i*4,temp - i * 4);
			tls_gpio_write(18, 1);
#endif			
			
			for(i = 0;i < temp; i++)
			{
				printf("[%d]=[%x]\r\n",i,buf[i]);
			}
		}
	}
}

u8 TestSPITransferData(void)
{
	u32 i = 0;
	u8 cmd[40];
	u8 buf[40];
	u8 *TXBuf;
	int time;
//	int ret;

	TXBuf = tls_mem_alloc(TEST_SPI_SPEED_SIZE);
	if(NULL == TXBuf)
		return 0;
	memset(TXBuf,0xaa,TEST_SPI_SPEED_SIZE);
	
	memset(cmd,0,32);
	memset(buf,0,32);
	cmd[0] = 0x03;
	while(1)
	{		
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 0);
#endif
		tls_spi_write_then_read(cmd, 1, buf, 2);
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 1);
#endif
		if(buf[0] & 0x01)
			break;
		OSTimeDly(1);
		printf("\ncan not tx data\n");
	}

	cmd[0] =0x00;
	*TXBuf = 0x90;	//命令字
	time = OSTimeGet();
	printf("\ntime1 = %d\n",time);
	for(i = 0;i < 1000;i ++)
	{
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 0);
#endif	
		tls_spi_write(TXBuf,TEST_SPI_SPEED_SIZE);
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 1);
#endif
	}
	time = OSTimeGet();
	printf("\ntime2 = %d\n",time);
	printf("\ntx cnt =%d\n",i);	
	tls_mem_free(TXBuf);
	
	return	0;
}

u8 TestSPITransferCMD(void)
{
	u8 buf[40];
	u8 cmd[100];
	u16 ret;

	memset(buf,0,32);
	memset(cmd,0,100);

	cmd[0] = 0x03;	//命令字一个byte之后，不能跟0，否则命令下面识别不对
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 0);
#endif
	tls_spi_write_then_read(cmd, 1, buf, 2);
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 1);
#endif
	printf("\ntx cmd[%x][%x]\n",buf[0],buf[1]);
	//OSTimeDly(10);

#if 1
	if(buf[0]&0x02)
	{

		cmd[0] = 0x91;
		cmd[1] = 0xaa;
		cmd[2] = 0x01;	//TYPE 命令端口传输 jj
		cmd[3] = 0x00;	//
		cmd[4] = 0x04;	//数据长度 4byte
		cmd[5] = 0x00;	//序号0
		cmd[6] = 0x00;	//FLG
		cmd[7] = 0x00;	//DA
		cmd[8] = 0X05;	//CHK
/*获取版本号*/

		cmd[9] = 0X01;	//精简指令获取版本号
		cmd[10] = 0X07;	
		cmd[11] = 0X00;	
		cmd[12] = 0X00;	
		cmd[13] = 0X08;	//CHK	
		cmd[14] = 0;
		cmd[15] = 0;
		cmd[16] = 0;
		//while(1)
			{
		//	temp = *((u32 *)cmd);
		//	printf("\ntemp = %x\n",temp);
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 0);
#endif
			ret = tls_spi_write(cmd,20);	//写精简指令
#if 	CS_CTRL_SOFT
		tls_gpio_write(18, 1);
#endif			
			printf("\nret =%d\n",ret);
		//	OSTimeDly(10);
			}

		
	}
#endif
return 0;
}


int spi_demo(char *buf)
{
//	int time;
	
	tls_spi_slave_sel(SPI_SLAVE_CARD);
		
	tls_spi_trans_type(2);
	tls_spi_setup(TLS_SPI_MODE_0, TLS_SPI_CS_LOW, 100000);
#if 	CS_CTRL_SOFT
	tls_reg_write32(HR_IOCTL_GP_SPI, 2);	//cs 作为gpio18使用
	tls_gpio_cfg(18, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_PULLLOW);
#endif
	TestSPIReceiveData();	
#if 1	
	//	while(1)
		{
	TestSPITransferCMD();
	TestSPIReceiveData();
	OSTimeDly(10);
		}
#endif		
#if 0
	time = OSTimeGet();
	printf("\ntime1 = %d\n",time);
	for(i = 0;i < 1000;i ++)
#endif		
		{
	//TestSPITransferData();
		}
#if 0
	time = OSTimeGet();
	printf("\ntime1 = %d\n",time);
#endif	

	return WM_SUCCESS;
}


#endif
