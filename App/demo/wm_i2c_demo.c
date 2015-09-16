/***************************************************************************** 
* 
* File Name : wm_i2c_demo.c 
* 
* Description: i2c demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-8-13 
*****************************************************************************/ 
#include "wm_include.h"
#include "wm_i2c.h"
#include <string.h>
#if DEMO_I2C

//��AT24CXXָ����ַ��������
//ReadAddr : ��ʼ�����ĵ�ַ
//����ֵ:����������
u8 AT24CXX_ReadOneByte(u16 ReadAddr)
{				  
	u8 temp=0;		  	    																 
	//printf("\nread addr=%x\n",ReadAddr);
	tls_i2c_write_byte(0XA0,1);   
	tls_i2c_wait_ack(); 
    	tls_i2c_write_byte(ReadAddr,0);   
	tls_i2c_wait_ack();	    

	tls_i2c_write_byte(0XA1,1);
	tls_i2c_wait_ack();	 
	temp=tls_i2c_read_byte(0,1);
	//printf("\nread byte=%x\n",temp);
	return temp;
}


void AT24CXX_ReadLenByte(u16 ReadAddr,u8 *pBuffer,u16 NumToRead)
{				  
	//printf("\nread len addr=%x\n",ReadAddr);
	tls_i2c_write_byte(0XA0,1);   
	tls_i2c_wait_ack(); 
    	tls_i2c_write_byte(ReadAddr,0);   
	tls_i2c_wait_ack();	    
	tls_i2c_write_byte(0XA1,1);
	tls_i2c_wait_ack();	
	while(NumToRead > 1)
	{
		*pBuffer++ = tls_i2c_read_byte(1,0);
		//printf("\nread byte=%x\n",*(pBuffer - 1));
		NumToRead --;
	}
   	*pBuffer = tls_i2c_read_byte(0,1);
}



//��AT24CXXָ����ַд������
//WriteAddr: Ŀ�ĵ�ַ
//DataToWrite: Ҫд�������
void AT24CXX_WriteOneByte(u16 WriteAddr,u8 DataToWrite)
{				   	  	    																 
	tls_i2c_write_byte(0XA0,1); 
	tls_i2c_wait_ack();	   
	tls_i2c_write_byte(WriteAddr,0);
	tls_i2c_wait_ack(); 	 										  		   
	tls_i2c_write_byte(DataToWrite,0); 				   
	tls_i2c_wait_ack();  	   
 	tls_i2c_stop();
	tls_os_time_delay(1);
}


//���AT24CXX�Ƿ�����
//��������24CXX���һ����ַ( 255)���洢��־��
//���������24Cϵ�У������ַ��Ҫ�޸�
//����1:���ʧ��
//����0:���ɹ�
u8 AT24CXX_Check(void)
{
	u8 temp;
	temp=AT24CXX_ReadOneByte(255);
	if(temp==0X55)return 0;		   
	else
	{
		AT24CXX_WriteOneByte(255,0X55);
		tls_os_time_delay(1);
		temp=AT24CXX_ReadOneByte(255);	  
		if(temp==0X55)return 0;
	}

	return 1;											  
}

//��AT24CXXָ����ַ����ָ������������
//��ʼ�����ĵ�ַ 24c02��(0-255)
//pBuffer:	���������׵�ַ
//NumToRead:	Ҫ���������ݸ���
void AT24CXX_Read(u16 ReadAddr,u8 *pBuffer,u16 NumToRead)
{
	while(NumToRead)
	{
		*pBuffer++=AT24CXX_ReadOneByte(ReadAddr++);	
		NumToRead--;
	}
}  

//��AT24CXXָ����ַд��ָ������������
//WriteAddr	: Ŀ�ĵ�ַ
//pBuffer		:Ҫд�������
//NumToWrite:	Ҫд������ݸ���
void AT24CXX_Write(u16 WriteAddr,u8 *pBuffer,u16 NumToWrite)
{
	while(NumToWrite--)
	{
		AT24CXX_WriteOneByte(WriteAddr,*pBuffer);
		WriteAddr++;
		pBuffer++;
	}
}
 

//i2c demo ���豸�� EEPROM (at24c02)
int i2c_demo(char *buf)
{
	u8 testbuf[] = {"AT24CXX I2C TEST OK"};
	u8 datatmp[32];
	
	tls_i2c_init();

	while(AT24CXX_Check())
	{
		printf("\nAT24CXX check faild\n");
	}
	tls_os_time_delay(1);
	printf("\nAT24CXX check success\n");

	AT24CXX_Write(0,(u8 *)testbuf,sizeof(testbuf));
	tls_os_time_delay(1);
	memset(datatmp,0,sizeof(datatmp));
	//AT24CXX_Read(0,datatmp,sizeof(testbuf));//���ֶ���ʽ����
	AT24CXX_ReadLenByte(0,(u8 *)datatmp,sizeof(testbuf));
	printf("\nread data is:%s\n",datatmp);
	
	return WM_SUCCESS;
}

#endif
