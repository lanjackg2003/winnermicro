/**
******************************************************************************
* @file     zc_hf_adpter.c
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    Event
******************************************************************************
*/
#include <zc_protocol_controller.h>
#include <zc_timer.h>
#include <zc_module_interface.h>
#include <zc_hf_adpter.h>
#include <ac_api.h>
#include <stdlib.h>
#include "errno.h"
#include "wm_osal.h"
#include "wm_flash.h"
#include "wm_sockets.h"
#include "lwip/inet.h"
#include "wm_include.h"
#include "wm_fwup.h"
#include "wm_cpu.h" 
#define USER_FLASH_PARAM1_ADDR	(0xF8000)
#define USER_FLASH_PARAM2_ADDR	(0xF9000)

extern PTC_ProtocolCon  g_struProtocolController;
PTC_ModuleAdapter g_struHfAdapter;

MSG_Buffer g_struRecvBuffer;
MSG_Buffer g_struRetxBuffer;
MSG_Buffer g_struClientBuffer;


MSG_Queue  g_struRecvQueue;
MSG_Buffer g_struSendBuffer[MSG_BUFFER_SEND_MAX_NUM];
MSG_Queue  g_struSendQueue;

u8 g_u8MsgBuildBuffer[MSG_BULID_BUFFER_MAXLEN];
u8 g_u8ClientSendLen = 0;


u16 g_u16TcpMss;
u16 g_u16LocalPort;


u8 g_u8recvbuffer[HF_MAX_SOCKET_LEN];
ZC_UartBuffer g_struUartBuffer;
HF_TimerInfo g_struHfTimer[ZC_TIMER_MAX_NUM];
tls_os_sem_t *g_struTimermutex;
u8  g_u8BcSendBuffer[60];
u32 g_u32BcSleepCount;
struct sockaddr_in struRemoteAddr;

#define TASK_HF_Cloudfunc_STK_SIZE           400            /* Size of each task's stacks (# of WORDs)  */

OS_STK TaskHFCloudfuncStk[TASK_HF_Cloudfunc_STK_SIZE];        /* Tasks stacks */


u32 g_u32session_id;

extern tls_os_queue_t *App_R_Q;
/*************************************************
* Function: HF_ReadDataFromFlash
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_ReadDataFromFlash(u8 *pu8Data, u16 u16Len)
{

    tls_fls_read(USER_FLASH_PARAM1_ADDR, pu8Data, u16Len);
}
/*************************************************
* Function: HF_WriteDataToFlash
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_WriteDataToFlash(u8 *pu8Data, u16 u16Len)
{
    tls_fls_write(USER_FLASH_PARAM1_ADDR, (u8*)pu8Data, u16Len);
}
/*************************************************
* Function: HF_get_timer_id
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u8 HF_get_timer_id(hftimer_handle_t handle)
{
    u8 u8TimerId;

    for(u8TimerId = 0; u8TimerId < ZC_TIMER_MAX_NUM; ++u8TimerId)
    {
        if(g_struHfTimer[u8TimerId].struHandle == handle)
        {
            return u8TimerId;
        }
    }

    return 0xff;
}

/*************************************************
* Function: HF_timer_callback
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_timer_callback(void *ptmr, void *parg)
{
    hftimer_handle_t htimer = ptmr;
    u8 u8TimerId;
    tls_os_sem_acquire(g_struTimermutex, 0);
    u8TimerId = HF_get_timer_id(htimer);

    TIMER_TimeoutAction(u8TimerId);
    TIMER_StopTimer(u8TimerId);

    tls_os_sem_release(g_struTimermutex);
}



/*************************************************
* Function: HF_StopTimer
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_StopTimer(u8 u8TimerIndex)
{
    tls_os_timer_Del(g_struHfTimer[u8TimerIndex].struHandle);
}

/*************************************************
* Function: HF_SetTimer
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u32 HF_SetTimer(u8 u8Type, u32 u32Interval, u8 *pu8TimeIndex)
{
    tls_os_status_t status;
    u8 u8TimerIndex;
    u32 u32Retval;

    u32Retval = TIMER_FindIdleTimer(&u8TimerIndex);
    if (ZC_RET_OK == u32Retval)
    {
        status = tls_os_timer_create(&g_struHfTimer[u8TimerIndex].struHandle,
                                HF_timer_callback,
                                0, (u32Interval*HZ)/1000,
                                false, NULL);
        if(TLS_OS_SUCCESS != status)
        {
            ZC_Printf("fengq: create timer error, 0x%x!\n", status);
            return ZC_RET_ERROR;
        }
        
        TIMER_AllocateTimer(u8Type, u8TimerIndex, (u8*)&g_struHfTimer[u8TimerIndex]);
        g_struHfTimer[u8TimerIndex].u32FirstFlag = 1;
        tls_os_timer_start((tls_os_timer_t *)g_struHfTimer[u8TimerIndex].struHandle);
        *pu8TimeIndex = u8TimerIndex;
    }
    else
    {
        ZC_Printf("fengq: find no timer!\n");
    }

    return u32Retval;
}

/*************************************************
* Function: HF_FirmwareUpdateFinish
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u32 HF_FirmwareUpdateFinish(u32 u32TotalLen)
{
    tls_fwup_exit(g_u32session_id);
    return ZC_RET_OK;
}


/*************************************************
* Function: HF_FirmwareUpdate
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u32 HF_FirmwareUpdate(u8 *pu8FileData, u32 u32Offset, u32 u32DataLen)
{
    int retval;

    if (0 == u32Offset)
    {
        g_u32session_id = tls_fwup_enter(TLS_FWUP_IMAGE_SRC_WEB);
        if(g_u32session_id == 0)
        {
            return ZC_RET_ERROR;
        }
    }

    retval = tls_fwup_request_sync(g_u32session_id, pu8FileData, u32DataLen);
    if (retval < 0)
    {
        return ZC_RET_ERROR;
    }
    
    return ZC_RET_OK;

}

/*************************************************
* Function: HF_SendDataToMoudle
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u32 HF_SendDataToMoudle(u8 *pu8Data, u16 u16DataLen)
{
#ifdef ZC_MODULE_DEV
    //AC_RecvMessage((ZC_MessageHead *)pu8Data);
    tls_os_status_t Status;
    Status = tls_os_queue_send(App_R_Q, pu8Data, u16DataLen);
    if(Status)
    {
        ZC_Printf("fengq: send message error!\n");
    }
#else
  	u8 u8MagicFlag[4] = {0x02,0x03,0x04,0x05};
    tls_uart_tx_sync((char*)u8MagicFlag,4); 
    tls_uart_tx_sync((char *)pu8Data, u16DataLen);  
#endif      
    return ZC_RET_OK;
}


/*************************************************
* Function: HF_Rest
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_Rest(void)
{
    tls_wifi_set_oneshot_flag(1);
}
/*************************************************
* Function: HF_SendTcpData
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_SendTcpData(u32 u32Fd, u8 *pu8Data, u16 u16DataLen, ZC_SendParam *pstruParam)
{
    u16 u16SendLen = 0;
    s32 s32TmpLen;

    while(u16SendLen < u16DataLen)
    {
        s32TmpLen = send(u32Fd, pu8Data + u16SendLen, u16DataLen - u16SendLen, 0);
        if(s32TmpLen < 0)
        {
            ZC_Printf("fengq: send error!\n");
            return;
        }
        u16SendLen += s32TmpLen;
    }
}
/*************************************************
* Function: HF_SendUdpData
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_SendUdpData(u32 u32Fd, u8 *pu8Data, u16 u16DataLen, ZC_SendParam *pstruParam)
{
    sendto(u32Fd,(char*)pu8Data,u16DataLen,0,
        (struct sockaddr *)pstruParam->pu8AddrPara,
        sizeof(struct sockaddr_in));
}

/*************************************************
* Function: HF_CloudRecvfunc
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_CloudRecvfunc(void* arg)
{
    s32 s32RecvLen=0;
    fd_set fdread;
    u32 u32Index;
    u32 u32Len=0;
    u32 u32ActiveFlag = 0;
    struct sockaddr_in cliaddr;
    int connfd;
    extern u8 g_u8ClientStart;
    u32 u32MaxFd = 0;
    struct timeval timeout;
    struct sockaddr_in addr;
    int tmp=1;
    s8 s8ret = 0;
    
    ZC_StartClientListen();

    u32ActiveFlag = 0;

    timeout.tv_sec= 0;
    timeout.tv_usec= 1000;

    FD_ZERO(&fdread);

    FD_SET(g_Bcfd, &fdread);
    u32MaxFd = u32MaxFd > g_Bcfd ? u32MaxFd : g_Bcfd;

    if (PCT_INVAILD_SOCKET != g_struProtocolController.struClientConnection.u32Socket)
    {
        FD_SET(g_struProtocolController.struClientConnection.u32Socket, &fdread);
        u32MaxFd = u32MaxFd > g_struProtocolController.struClientConnection.u32Socket ? u32MaxFd : g_struProtocolController.struClientConnection.u32Socket;
        u32ActiveFlag = 1;
    }

    if ((g_struProtocolController.u8MainState >= PCT_STATE_WAIT_ACCESSRSP)
    && (g_struProtocolController.u8MainState < PCT_STATE_DISCONNECT_CLOUD))
    {
        FD_SET(g_struProtocolController.struCloudConnection.u32Socket, &fdread);
        u32MaxFd = u32MaxFd > g_struProtocolController.struCloudConnection.u32Socket ? u32MaxFd : g_struProtocolController.struCloudConnection.u32Socket;
        u32ActiveFlag = 1;
    }


    for (u32Index = 0; u32Index < ZC_MAX_CLIENT_NUM; u32Index++)
    {
        if (0 == g_struClientInfo.u32ClientVaildFlag[u32Index])
        {
            FD_SET(g_struClientInfo.u32ClientFd[u32Index], &fdread);
            u32MaxFd = u32MaxFd > g_struClientInfo.u32ClientFd[u32Index] ? u32MaxFd : g_struClientInfo.u32ClientFd[u32Index];
            u32ActiveFlag = 1;
        }
    }

    if (0 == u32ActiveFlag)
    {
        return ;
    }

    s8ret = select(u32MaxFd + 1, &fdread, NULL, NULL, &timeout);
    if(s8ret<=0)
    {
       return;
    }
    if ((g_struProtocolController.u8MainState >= PCT_STATE_WAIT_ACCESSRSP)
    && (g_struProtocolController.u8MainState < PCT_STATE_DISCONNECT_CLOUD))
    {
        if (FD_ISSET(g_struProtocolController.struCloudConnection.u32Socket, &fdread))
        {
            s32RecvLen = recv(g_struProtocolController.struCloudConnection.u32Socket, g_u8recvbuffer, HF_MAX_SOCKET_LEN, 0);
            if(s32RecvLen > 0)
            {
                ZC_Printf("recv data len = %d\n", s32RecvLen);
                MSG_RecvDataFromCloud(g_u8recvbuffer, s32RecvLen);
            }
            else
            {
                ZC_Printf("recv error, len = %d\n",s32RecvLen);
                PCT_DisConnectCloud(&g_struProtocolController);

                g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
                g_struUartBuffer.u32RecvLen = 0;
            }
        }

    }


    for (u32Index = 0; u32Index < ZC_MAX_CLIENT_NUM; u32Index++)
    {
        if (0 == g_struClientInfo.u32ClientVaildFlag[u32Index])
        {
            if (FD_ISSET(g_struClientInfo.u32ClientFd[u32Index], &fdread))
            {
                s32RecvLen = recv(g_struClientInfo.u32ClientFd[u32Index], g_u8recvbuffer, HF_MAX_SOCKET_LEN, 0);
                if (s32RecvLen > 0)
                {
                    ZC_RecvDataFromClient(g_struClientInfo.u32ClientFd[u32Index], g_u8recvbuffer, s32RecvLen);
                }
                else
                {
                    ZC_ClientDisconnect(g_struClientInfo.u32ClientFd[u32Index]);
                    closesocket(g_struClientInfo.u32ClientFd[u32Index]);
                }

            }
        }

    }

    if (PCT_INVAILD_SOCKET != g_struProtocolController.struClientConnection.u32Socket)
    {
        if (FD_ISSET(g_struProtocolController.struClientConnection.u32Socket, &fdread))
        {
            connfd = accept(g_struProtocolController.struClientConnection.u32Socket,(struct sockaddr *)&cliaddr,&u32Len);

            if (ZC_RET_ERROR == ZC_ClientConnect((u32)connfd))
            {
                closesocket(connfd);
            }
            else
            {
                ZC_Printf("accept client = %d\n", connfd);
            }
        }
    }

    if (FD_ISSET(g_Bcfd, &fdread))
    {
        tmp = sizeof(addr);
        s32RecvLen = recvfrom(g_Bcfd, g_u8BcSendBuffer, 100, 0, (struct sockaddr *)&addr, (socklen_t*)&tmp);
        if(s32RecvLen > 0)
        {
            ZC_SendClientQueryReq(g_u8BcSendBuffer, (u16)s32RecvLen);
        }
    }
}

/*************************************************
* Function: HF_GetMac
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void HF_GetMac(u8 *pu8Mac)
{
    u8 mac_addr[8] = {0};
    tls_get_mac_addr(mac_addr);
    ZC_HexToString(pu8Mac,mac_addr,6);
}

/*************************************************
* Function: HF_Reboot
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void HF_Reboot(void)
{
    tls_sys_reset();
}

/*************************************************
* Function: HF_ConnectToCloud
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u32 HF_ConnectToCloud(PTC_Connection *pstruConnection)
{
    int fd;
    struct sockaddr_in addr;
    struct ip_addr struIp;
    int retval;
    u16 port;
    struct hostent* HostEntry;
    memset((char*)&addr,0,sizeof(addr));
    if (1 == g_struZcConfigDb.struSwitchInfo.u32ServerAddrConfig)
    {
        ZC_Printf("fengq: connect cloud test addr!\n");
        port = g_struZcConfigDb.struSwitchInfo.u16ServerPort;
        struIp.addr = htonl(g_struZcConfigDb.struSwitchInfo.u32ServerIp);
        retval = ZC_RET_OK;
    }
    else
    {
        port = ZC_CLOUD_PORT;
        HostEntry = gethostbyname((const char *)g_struZcConfigDb.struCloudInfo.u8CloudAddr);
        if(HostEntry)
        {
            struIp.addr = *((u32 *)HostEntry->h_addr_list[0]);
            retval = ZC_RET_OK;
        }
        else
        {
            retval = ZC_RET_ERROR;
        }
    }

    if (ZC_RET_OK != retval)
    {
        return ZC_RET_ERROR;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr=struIp.addr;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
    {
        ZC_Printf("fengq: socket error!\n");
        return ZC_RET_ERROR;
    }

    ZC_Printf("fengq: addr = %x, prot = 0x%x\n", addr.sin_addr.s_addr, addr.sin_port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        ZC_Printf("fengq: connect cloud failed!\n");
        closesocket(fd);
        if(g_struProtocolController.struCloudConnection.u32ConnectionTimes++ > 20)
        {
           g_struZcConfigDb.struSwitchInfo.u32ServerAddrConfig = 0;
        }

        return ZC_RET_ERROR;
    }

    g_struProtocolController.struCloudConnection.u32ConnectionTimes = 0;
    g_struProtocolController.struCloudConnection.u32Socket = fd;


    ZC_Rand(g_struProtocolController.RandMsg);

    return ZC_RET_OK;
}
/*************************************************
* Function: HF_ConnectToCloud
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u32 HF_ListenClient(PTC_Connection *pstruConnection)
{
    int fd;
    struct sockaddr_in servaddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0)
        return ZC_RET_ERROR;

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port = htons(pstruConnection->u16Port);
    if(bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        closesocket(fd);
        return ZC_RET_ERROR;
    }

    if (listen(fd, 4) < 0)
    {
        closesocket(fd);
        return ZC_RET_ERROR;
    }

    ZC_Printf("Tcp Listen Port = %d\n", pstruConnection->u16Port);
    g_struProtocolController.struClientConnection.u32Socket = fd;

    return ZC_RET_OK;
}

/*************************************************
* Function: HF_BcInit
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_BcInit(void)
{
    int tmp=1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ZC_MOUDLE_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    g_Bcfd = socket(AF_INET, SOCK_DGRAM, 0);

    tmp = 1;
    setsockopt(g_Bcfd, SOL_SOCKET, SO_BROADCAST, &tmp, sizeof(tmp));

    bind(g_Bcfd, (struct sockaddr*)&addr, sizeof(addr));
    g_struProtocolController.u16SendBcNum = 0;

    memset((char*)&struRemoteAddr, 0, sizeof(struRemoteAddr));
    struRemoteAddr.sin_family = AF_INET;
    struRemoteAddr.sin_port = htons(ZC_MOUDLE_BROADCAST_PORT);
    struRemoteAddr.sin_addr.s_addr=inet_addr("255.255.255.255");
    g_pu8RemoteAddr = (u8*)&struRemoteAddr;
    g_u32BcSleepCount = 8;

    return;
}

/*************************************************
* Function: HF_Cloudfunc
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_Cloudfunc(void* arg)
{
    int fd;
    u32 u32Timer = 0;
    HF_BcInit();

    while(1)
    {
        tls_os_time_delay(10);
        fd = g_struProtocolController.struCloudConnection.u32Socket;
        PCT_Run();
        HF_CloudRecvfunc(NULL);
        if (PCT_STATE_DISCONNECT_CLOUD == g_struProtocolController.u8MainState)
        {
            closesocket(fd);
            if(0==g_struProtocolController.struCloudConnection.u32ConnectionTimes)
            {
                u32Timer = 1000;
            }
            else
            {
                u32Timer = rand();
                u32Timer = (PCT_TIMER_INTERVAL_RECONNECT) * (u32Timer % 10 + 1);
            }
            ZC_Printf("reconect timer = %d\n", u32Timer);
            PCT_ReconnectCloud(&g_struProtocolController, u32Timer);
            g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
            g_struUartBuffer.u32RecvLen = 0;
        }
        else
        {
            MSG_SendDataToCloud((u8*)&g_struProtocolController.struCloudConnection);
        }
        ZC_SendBc();
    }
}

/*************************************************
* Function: HF_Init
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_Init()
{
    tls_os_status_t status;

    g_struHfAdapter.pfunConnectToCloud = HF_ConnectToCloud;
    g_struHfAdapter.pfunListenClient = HF_ListenClient;
    g_struHfAdapter.pfunSendTcpData = HF_SendTcpData;
    g_struHfAdapter.pfunUpdate = HF_FirmwareUpdate;
    g_struHfAdapter.pfunUpdateFinish = HF_FirmwareUpdateFinish;
    g_struHfAdapter.pfunSendToMoudle = HF_SendDataToMoudle;
    g_struHfAdapter.pfunSetTimer = HF_SetTimer;
    g_struHfAdapter.pfunStopTimer = HF_StopTimer;

    g_struHfAdapter.pfunRest = HF_Rest;
    g_struHfAdapter.pfunWriteFlash = HF_WriteDataToFlash;
    g_struHfAdapter.pfunReadFlash = HF_ReadDataFromFlash;
    g_struHfAdapter.pfunSendUdpData = HF_SendUdpData;
    g_struHfAdapter.pfunGetMac = HF_GetMac;
    g_struHfAdapter.pfunReboot = HF_Reboot;
    
    g_struHfAdapter.pfunPrintf = (pFunPrintf)printf;
    g_struHfAdapter.pfunMalloc = malloc;
    g_struHfAdapter.pfunFree = free;
    g_u16TcpMss = 1000;
    PCT_Init(&g_struHfAdapter);

    g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
    g_struUartBuffer.u32RecvLen = 0;

    status = tls_os_task_create(NULL, NULL, HF_Cloudfunc, (void *)0,
                           (void *)TaskHFCloudfuncStk, TASK_HF_Cloudfunc_STK_SIZE * sizeof(u32),
                            50, 0);
    ZC_Printf("MT Init\n"); 
    if(status)
    {
        ZC_Printf("fengq: create HF_Cloudfunc task error!\n");
    }

    status = tls_os_sem_create(&g_struTimermutex, 1);
    if(status)
    {
        ZC_Printf("fengq: create timer mutex error!\n");
    } 
}

/*************************************************
* Function: HF_WakeUp
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_WakeUp()
{
    PCT_WakeUp();
}
/*************************************************
* Function: HF_Sleep
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void HF_Sleep()
{
    u32 u32Index;

    closesocket(g_Bcfd);

    if (PCT_INVAILD_SOCKET != g_struProtocolController.struClientConnection.u32Socket)
    {
        closesocket(g_struProtocolController.struClientConnection.u32Socket);
        g_struProtocolController.struClientConnection.u32Socket = PCT_INVAILD_SOCKET;
    }

    if (PCT_INVAILD_SOCKET != g_struProtocolController.struCloudConnection.u32Socket)
    {
        closesocket(g_struProtocolController.struCloudConnection.u32Socket);
        g_struProtocolController.struCloudConnection.u32Socket = PCT_INVAILD_SOCKET;
    }

    for (u32Index = 0; u32Index < ZC_MAX_CLIENT_NUM; u32Index++)
    {
        if (0 == g_struClientInfo.u32ClientVaildFlag[u32Index])
        {
            closesocket(g_struClientInfo.u32ClientFd[u32Index]);
            g_struClientInfo.u32ClientFd[u32Index] = PCT_INVAILD_SOCKET;
        }
    }

    PCT_Sleep();

    g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
    g_struUartBuffer.u32RecvLen = 0;
}

/*************************************************
* Function: AC_UartSend
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void AC_UartSend(u8* inBuf, u32 datalen)
{
    tls_uart_tx_sync((char *)inBuf, datalen);  
}
/******************************* FILE END ***********************************/


