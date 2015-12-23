#ifndef USER_MAIN_H
#define USER_MAIN_H

#include <string.h>
#include "wm_irq.h"
#include "tls_sys.h"
#include "wm_gpio.h"
#include "wm_params.h"
#include "wm_hostspi.h"
#include "wm_debug.h"
#if (GCC_COMPILE==1)
#include "wm_cmdp_hostif_gcc.h"
#else
#include "wm_cmdp_hostif.h"
#endif
#include "wm_config.h"
#include "wm_osal.h"
#include "wm_adc.h"
#include "wm_sockets.h"

#define USER_QUEUE_SIZE				64		// �û���Ϣ���е�size
#define USER_TASK_SIZE					1024	// �û�����ջ��size
#define USER_TASK_PRO					60		// �û��������ȼ�

#define KEY_SCAN_TIME					50		// һ�����ð���ɨ��ʱ��500ms
#define KEY_IO_ONESHOT					11		// һ������ʹ�õ�IO

#define USER_UART_BAUDRATE			115200

#define MSG_NET_UP						1		// �����ɹ���Ϣ
#define MSG_NET_DOWN					2		// ������Ϣ
#define MSG_TIMER						3		// ��ʱ����Ϣ
#define MSG_ONESHOT					4		// ����һ��������Ϣ

#define MSG_SK_CLIENT_ERR				5		// socket client ������Ϣ
#define MSG_SK_CLIENT_RX_DATA			6		// socket clent ���յ��������Ϣ

#define MSG_SK_SERVER_ERR				8		// socket client ������Ϣ
#define MSG_SK_SERVER_RX_DATA		9		// socket clent ���յ��������Ϣ

#define MSG_UART_RX_DATA		10		// socket clent ���յ��������Ϣ

#define UDP_BROAD_TIME				(100*10)	// UDP ʱ����10s

#define TCP_RXBUFF_MAX					512		// TCP recive buff size
#define TCP_TXBUFF_MAX					512		// TCP send buff size
#define TCP_SERVER_NUM				4		// ����ͬʱ���ӵ��豸��

#define UART_RXBUFF_MAX				1024	// uart rx buff size

typedef struct _USER_DEVICE_INFO
{
	INT32 wlan_status;				// 1 ??: 0 ??
	
	BOOL socket_ok;					// 1 socket ??: 0 socket ??
	INT8U socket_num;				// ?????socket ?
	INT8U is_raw; 					// 1:raw socket; 0:??socket
	
	INT8U rx_buff[TCP_RXBUFF_MAX];	// tcp recive buff
	INT32S rx_len;					// tcp recive buff len
	INT8U tx_buff[TCP_TXBUFF_MAX];	// tcp send buff
	INT32S tx_len;					// tcp send buff len
	
	INT8U uart_rx[UART_RXBUFF_MAX];	// uart recive buff
	INT16U wptr;						// uart recive buff write offset
	INT16U rptr;						// uart recive buff  report offset
	INT8U overflag;					// uart recive buff over
	INT8U MsgNum;					// uart recive data send to net number

}USER_DEVICE_INFO;

#endif
