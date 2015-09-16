/***************************************************************************** 
* 
* File Name : wm_adc_demo.c 
* 
* Description: adc demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-8-18
*****************************************************************************/ 
#include "wm_include.h"
#include "wm_adc.h"
#define ADC_WITH_CPU	0
#if DEMO_ADC

#if ADC_WITH_CPU
static void adc_cb_demo(u16 *buf, u16 len)
{
	//只有一个数据
	printf("\nadc int result=%x\n",*buf);

	//tls_adc_start_with_cpu(1, ADC_SAMPLE_ACCURACY_12Bits);
}
#else
static void adc_dma_cb_demo(u16 *buf, u16 len)
{
	int i;
	printf("\nadc dma cb len=%d\n",len);

	for(i = 0;i < len;i ++)
	{
		printf("\n[%d]==%x",i,*(buf + i));
	}
	//tls_adc_start_with_dma(0, ADC_SAMPLE_ACCURACY_12Bits, 100);
}
#endif
int adc_demo(char *buf)
{
#if ADC_WITH_CPU
	tls_adc_init(0, 0);
	tls_adc_irq_register(ADC_INT_TYPE_ADC, adc_cb_demo);
	tls_adc_start_with_cpu(1, ADC_SAMPLE_ACCURACY_12Bits);
#else
	tls_adc_init(1, 2);	//申请dma通道2，可以改
	tls_adc_irq_register(ADC_INT_TYPE_DMA, adc_dma_cb_demo);
	tls_adc_start_with_dma(0, ADC_SAMPLE_ACCURACY_12Bits, 100);
#endif

	return 	WM_SUCCESS;
}

#endif
