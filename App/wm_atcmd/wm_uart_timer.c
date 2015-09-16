/***************************************************************************** 
* 
* File Name : wm_uart_timer.c
* 
* Description: Timer for uart Module 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-12 
*****************************************************************************/ 
#include "wm_regs.h"
#include "wm_timer.h"
#include "wm_uart_task.h"
#include "wm_osal.h"
#include "wm_irq.h"

void tls_timer2_stop(void)
{
	tls_reg_write32(HR_TIMER2_CSR, TLS_TIMER_INT_CLR);
}

void tls_timer2_start(u32 timeout)
{
    u32 timer_csr;	
	tls_reg_write32(HR_TIMER2_CSR, TLS_TIMER_INT_CLR);
	if (timeout){
    	timer_csr = (1000*timeout << TLS_TIMER_VALUE_S) | TLS_TIMER_ONE_TIME ;
    	tls_reg_write32(HR_TIMER2_CSR, timer_csr);
	}
    tls_reg_write32(HR_TIMER2_CSR, tls_reg_read32(HR_TIMER2_CSR) |TLS_TIMER_INT_EN| TLS_TIMER_EN);
}

void tls_timer2_isr(void *data)
{
    u32 value;
    struct tls_uart *uart = (struct tls_uart *)data;

    tls_timer2_stop();
    uart->rx_idle = true;
    tls_os_mailbox_send(uart->rx_mailbox, (void *)MBOX_MSG_UART_RX); 

 	/* clear timer2 interrupt */
    value = tls_reg_read32(HR_TIMER2_CSR);
	tls_reg_write32(HR_TIMER2_CSR, value);
}

void tls_timer2_init(u32 timeout)
{
    u32 timer_csr;

	tls_reg_write32(HR_TIMER2_CSR, TLS_TIMER_INT_CLR);
    timer_csr = (timeout << TLS_TIMER_VALUE_S) | TLS_TIMER_ONE_TIME ;
    tls_reg_write32(HR_TIMER2_CSR, timer_csr);
    tls_reg_write32(HR_TIMER2_CSR, tls_reg_read32(HR_TIMER2_CSR) | TLS_TIMER_INT_EN|TLS_TIMER_EN);
}

void tls_timer2_irq_register(struct tls_uart *uart){
    tls_irq_register_handler(TIMER2_INT, tls_timer2_isr, uart);
    tls_irq_enable(TIMER2_INT);
}

