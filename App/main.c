/*****************************************************************************
*
* File Name : main.c
*
* Description: main
*
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*
* Author : dave
*
* Date : 2014-6-14
*****************************************************************************/
#include "wm_include.h"
#include <zc_hf_adpter.h>
#include "ac_api.h"
#include "ac_hal.h"
extern tls_os_sem_t    *libc_sem;
int main(void)
{
#if TLS_OS_UCOS
    tls_main();
    OSStart();      // 开始多任务调度
#elif TLS_OS_FREERTOS
    tls_irq_init();
    tls_os_sem_create(&libc_sem, 1);
    tls_main();
    vTaskStartScheduler();
#endif

    return 0;
}
#define APP_R_Q_SIZE                          3
tls_os_queue_t *App_R_Q = NULL;
void *App_R_Queue[APP_R_Q_SIZE];

//#define APP_S_Q_SIZE                          2
//tls_os_queue_t *App_S_Q = NULL;
//void *App_S_Queue[APP_S_Q_SIZE];

#define AppTask_STK_SIZE       1024
OS_STK AppTaskStk[AppTask_STK_SIZE];
void AppTask(void* arg);

extern void UserDeviceInit(void);
void CreateUserTask(void)
{
    printf("\n user task\n");
    UserDeviceInit();
#if DEMO_CONSOLE
    CreateDemoTask();
#endif
    /* +fengqiang*/
//    HF_Rest();
    HF_Init();
    AC_Init();
}


void RestoreParamToDefault(void)
{
#if 0
    struct tls_user_param *user_param = NULL;

    user_param = (struct tls_user_param *)tls_mem_alloc(sizeof(struct tls_user_param));
    if(NULL == user_param)
    {
        return -1;
    }
    memset(user_param, 0, sizeof(*user_param));
    user_param->wireless_protocol = 0;  // sta 0; adhoc 1; ap 2
    user_param->auto_mode = 1;
    user_param->baudrate = 9600;
    user_param->user_port_mode = 0;     // LUart 0; HUart 1; HSPI 2; SDIO 3
    user_param->dhcp_enable = 1;
    user_param->auto_powersave = 0;
    user_param->ip[0] = 192;
    user_param->ip[1] = 168;
    user_param->ip[2] = 1;
    user_param->ip[3] = 1;
    user_param->netmask[0] = 255;
    user_param->netmask[1] = 255;
    user_param->netmask[2] = 255;
    user_param->netmask[3] = 0;
    user_param->gateway[0] = 192;
    user_param->gateway[1] = 168;
    user_param->gateway[2] = 1;
    user_param->gateway[3] = 1;
    user_param->dns[0] = 192;
    user_param->dns[1] = 168;
    user_param->dns[2] = 1;
    user_param->dns[3] = 1;

    user_param->socket_protocol = 0;    // TCP 0; UDP 1
    user_param->socket_client_or_server = 0;    // client 0; server 1
    user_param->socket_port_num = 1000;
    memset(user_param->socket_host, 0, 32);
    memset(user_param->PassWord, '0', 6);

    tls_param_save_user(user_param);
    tls_mem_free(user_param);

    tls_param_to_default();
#endif
}
