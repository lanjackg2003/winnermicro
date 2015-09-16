/***************************************************************************** 
* 
* File Name : wm_flash_demo.c 
* 
* Description: flash demo function 
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
 
#if DEMO_FLASH

#define FLASH_CS_SOFT	0		//为了通过flash测试spi主接口
#define TEST_SPEED_SIZE		4000//5200//	2*1024

static void flash_spi_write_demo(u32 addr)
{
	u32 cmd;

	cmd = 0;
	cmd |= 0x03;	//read cmd
	cmd |= (((addr & 0xff) << 24) | ((addr & 0xff00) << 8) |((addr & 0xff0000) >> 8) & 0xffffff00);
//测试spi write接口
	tls_spi_write((const u8 *)&cmd, 4);
}


static void flash_spi_read_demo( u8 *buf, u32 len)
{
//测试spi read接口
	tls_spi_read(buf, len);
}


int flash_demo(char *buf)
{
	u8 testbuf[65];
	u8 testbuf2[65];
#if 1
	u8 *testspeed,*testspeed2;
	u32 time;
#endif	
	u16 i;

	tls_spi_slave_sel(SPI_SLAVE_FLASH);
	tls_spi_trans_type(0);
	tls_spi_setup(TLS_SPI_MODE_0, TLS_SPI_CS_LOW, 10000000);
	
	memset(testbuf,0,sizeof(testbuf));
#if 0
	for(i = 0;i < 64;i ++)
	{
		testbuf[i] = i + 1;
	}
#if 1	
//	tls_fls_write(0xf0000, testbuf, 64);
	tls_fls_write(0xf0003, testbuf, 31);
	tls_fls_write(0xf0003+31, testbuf+31, 33);
#endif
	printf("\nwrite success\n");
#if 	FLASH_CS_SOFT
	tls_reg_write32(HR_IOCTL_GP_SPI, 2);	//cs 作为gpio18使用
	tls_gpio_cfg(18, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_PULLLOW);
#endif
	memset(testbuf2, 0, sizeof(testbuf2));	
#if 	FLASH_CS_SOFT
	tls_gpio_write(18, 0);
	flash_spi_write_demo(0xf0000);
	flash_spi_read_demo(testbuf2, 31);
	flash_spi_read_demo(testbuf2 + 31, 33);
	tls_gpio_write(18, 1);
#else	
	tls_fls_read(0xf0003, testbuf2,64);
#endif
	printf("\n");
	for(i = 0;i < 64;i ++)
	{
		printf("[%x]",testbuf2[i]);
		if(i > 0 && 0 ==i%16)
			printf("\n");
	}
	if(0 == memcmp(testbuf,testbuf2,64))
	{
		printf("\nr w flash ok\n");
	}
	else
	{
		printf("\nr w flash fail\n");
	}
#else
	testspeed = tls_mem_alloc(TEST_SPEED_SIZE);
	if(NULL == testspeed)
	{
		printf("\nmalloc testspeed error\n");
		return -1;
	}
	memset(testspeed,0,TEST_SPEED_SIZE);
	for(i = 0;i < TEST_SPEED_SIZE;i ++)
	{
		testspeed[i] = i + 1;
	}

	tls_fls_write(0xf0003, testspeed, 1247);
	tls_fls_write(0xf0003 + 1247, testspeed + 1247, 2571);
	tls_fls_write(0xf0003 + 1247 + 2571, testspeed + 1247 + 2571, 182);

	testspeed2 = tls_mem_alloc(TEST_SPEED_SIZE);
	if(NULL == testspeed2)
	{
		printf("\ntest speed2 error\n");
		return -1;
	}
	memset(testspeed2,0,TEST_SPEED_SIZE);

#if 	FLASH_CS_SOFT
	tls_reg_write32(HR_IOCTL_GP_SPI, 2);	//cs 作为gpio18使用
	tls_gpio_cfg(18, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_PULLLOW);
	tls_gpio_write(18, 0);
	flash_spi_write_demo(0xf0000);
	flash_spi_read_demo(testspeed2, 4211);
	flash_spi_read_demo(testspeed2 + 4211, 907);
	flash_spi_read_demo(testspeed2 + 4211 + 907, 2);
	tls_gpio_write(18, 1);
#else	
	tls_fls_read(0xf0003, testspeed2,TEST_SPEED_SIZE);
#endif
	for(i = 0;i < TEST_SPEED_SIZE;i ++)
	{
		printf("[%x]",testspeed2[i]);
		if(i > 0 && 0 ==i%16)
			printf("\n");
	}
	if(0 == memcmp(testspeed,testspeed2,TEST_SPEED_SIZE))
	{
		printf("\nok\n");
	}
	else
	{
		printf("\nfail\n");
	}
	
	tls_mem_free(testspeed);
	tls_mem_free(testspeed2);
#endif	
#if 0
	testspeed = tls_mem_alloc(TEST_SPEED_SIZE);
	if(NULL == testspeed)
		return -1;
	//memset(testspeed,0xa5,TEST_SPEED_SIZE);
	for(i = 0;i < TEST_SPEED_SIZE;i ++)
	{
		testspeed[i] = i + 1;
	}
	time = OSTimeGet();
	printf("\ntime=%d\n",time);
	//for(i = 0;i < 1;i ++)
	//while(1)
		tls_fls_write(0xf0003, testspeed, TEST_SPEED_SIZE);
	time = OSTimeGet();
	printf("\nw time=%d\n",time);
	memset(testspeed,0,TEST_SPEED_SIZE);
	time = OSTimeGet();
	printf("\ntime=%d\n",time);
	for(i = 0;i < 1000;i ++)
	{
		memset(testspeed,0,TEST_SPEED_SIZE);
		tls_fls_read(0xf0000, testspeed,TEST_SPEED_SIZE);
	}
	time = OSTimeGet();
	printf("\nr time=%d\n",time);
	printf("\nspeed[0]= %x,mid=%x,speed end=%x\n",testspeed[0],testspeed[255], testspeed[TEST_SPEED_SIZE - 1]);
	if(testspeed[0] == 0xa5 && testspeed[TEST_SPEED_SIZE - 1] == 0xa5)
	{
		printf("\nok\n");
	}
	tls_mem_free(testspeed);

#endif	

	return WM_SUCCESS;
}

#endif
