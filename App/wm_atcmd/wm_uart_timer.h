/***************************************************************************** 
* 
* File Name : wm_uart_timer.h
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

#ifndef WM_UART_TIMER_H
#define WM_UART_TIMER_H
#include "wm_uart_task.h"

void tls_timer2_stop(void);
void tls_timer2_start(u32 timeout);
void tls_timer2_init(u32 timeout);
void tls_timer2_irq_register(struct tls_uart *uart);


#endif /* end of WM_UART_TIMER_H */
