/***************************************************************************** 
* 
* File Name : wm_hspi_task.c
* 
* Description: High speed spi task Module 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-9
*****************************************************************************/ 
#include <string.h>
#include "wm_hspi_task.h"
#include "wm_debug.h"
#include "wm_regs.h"
#include "wm_params.h"
#include "wm_mem.h"
#include "wm_hspi.h"
#if (GCC_COMPILE==1)
#include "wm_cmdp_hostif_gcc.h"
#else
#include "wm_cmdp_hostif.h"
#endif
#include "wm_config.h"
#include "wm_mem.h"


#if (TLS_CONFIG_HS_SPI && TLS_CONFIG_HOSTIF)
#define      HSPI_RX_TASK_STK_SIZE          512 
#define      HSPI_TX_TASK_STK_SIZE          512 


/*
 * hspi rx/tx task stack
 */

struct tls_hspi	g_hspi;
extern struct tls_slave_hspi	g_slave_hspi;

static int hspi_socket_recv(struct tls_hspi *hspi, 
        struct tls_hspi_tx_desc *tx_desc,
        struct tls_hostif_tx_msg *tx_msg)
{
    u16              offset;

    u8 skt_num = tx_msg->u.msg_tcp.sock;
    struct pbuf      *p; 
    u16              buflen, copylen;
    u8               head_size;
    struct tls_hostif_extaddr *extaddr;
    u16              total_len, padlen;
    struct tls_hostif *hif = tls_get_hostif();

    p = (struct pbuf *)tx_msg->u.msg_tcp.p; 
    buflen = p->tot_len;
    if(tx_msg->type == HOSTIF_TX_MSG_TYPE_UDP)
    {
        skt_num = skt_num | (1<<6);
        head_size = sizeof(struct tls_hostif_hdr) + sizeof(struct tls_hostif_extaddr); 
    }
    else
        head_size = sizeof(struct tls_hostif_hdr); 
    offset = tx_msg->offset;

    if (offset == buflen)
        return 0;

    //TLS_DBGPRT_INFO("pbuf len = %d, offset = %d\n", buflen, offset);

   do{
	    if ((buflen-offset) > (HSPI_TXBUF_SIZE - head_size))
	        copylen = HSPI_TXBUF_SIZE - head_size;
	    else
	        copylen = buflen-offset;

	    /* copy the contents of the received buffer into
	       hspi tx buffer */
	    copylen = pbuf_copy_partial(p, 
	            (u8 *)(tx_desc->buf_addr[0] + head_size + offset), 
	            copylen, offset);
	    offset += copylen;
		TLS_DBGPRT_INFO("copylen = %d, offset = %d\n", copylen, offset);
    }while(offset < p->tot_len);
    /* fill header */
    tls_hostif_fill_hdr(hif,
            (struct tls_hostif_hdr *)tx_desc->buf_addr[0],
            PACKET_TYPE_DATA,
            copylen, 0, skt_num, 0); 
    if(tx_msg->type == HOSTIF_TX_MSG_TYPE_UDP)
    {
        extaddr = (struct tls_hostif_extaddr *)(tx_desc->buf_addr[0] + 
                sizeof(struct tls_hostif_hdr));
        extaddr->ip_addr = tx_msg->u.msg_udp.ip_addr.addr;
        extaddr->remote_port = host_to_be16(tx_msg->u.msg_udp.port);
        extaddr->local_port = host_to_be16(tx_msg->u.msg_udp.localport);
    }
    /* fill hspi tx descriptor */
    total_len = copylen + head_size;
    padlen =  (4 - (total_len & 0x3)) & 0x3;
    total_len += padlen;
    tx_desc->buf_info = total_len << 12;
    /* enable hspi tx */
    tx_desc->valid_ctrl = (1UL<<31);
    tls_reg_write32(HR_SDIO_RXEN, 0x01);                
    if (offset >= p->tot_len) {
        offset = 0;
        pbuf_free(p);
    } else {
        tx_msg->offset = offset;
    }

    return offset;
}

static int hspi_tx_timeout_check(struct tls_hspi *hspi,
        struct tls_hspi_tx_desc *tx_desc)
{
    struct tls_hostif_tx_msg     *tx_msg;
    struct tls_hostif *hif = tls_get_hostif();
    u32 cpu_sr;

    /* check if host receive is stop, if stop, discard msg */
    if (tx_desc->valid_ctrl & BIT(31)) {
        while (1) {
            tx_msg = dl_list_first(&hspi->tx_msg_pending_list,
                    struct tls_hostif_tx_msg, list);
            if (!tx_msg)
                break;
            if (time_after(tls_os_get_time(), tx_msg->time + 60*HZ)) {
                switch (tx_msg->type) {
                    case HOSTIF_TX_MSG_TYPE_EVENT:
                        tls_mem_free(tx_msg->u.msg_cmdrsp.buf);
                        cpu_sr = tls_os_set_critical();
                        dl_list_del(&tx_msg->list);
                        dl_list_add_tail(&hif->tx_event_msg_list, &tx_msg->list);
                        tls_os_release_critical(cpu_sr);
                        break;

                    case HOSTIF_TX_MSG_TYPE_UDP:
                        pbuf_free(tx_msg->u.msg_udp.p);
                        cpu_sr = tls_os_set_critical();
                        dl_list_del(&tx_msg->list);
                        dl_list_add_tail(&hif->tx_msg_list, 
                                &tx_msg->list);
                        tls_os_release_critical(cpu_sr); 
                        break;

                    case HOSTIF_TX_MSG_TYPE_TCP:
                        pbuf_free(tx_msg->u.msg_tcp.p);
                        cpu_sr = tls_os_set_critical();
                        dl_list_del(&tx_msg->list);
                        dl_list_add_tail(&hif->tx_msg_list, 
                                &tx_msg->list);
                        tls_os_release_critical(cpu_sr); 
                        break;

                    default:
                        break;
                }
            } else {
                break;
            } 
        }
    }

    return 0; 
}

static int hspi_tx(struct tls_hspi *hspi)
{
    struct tls_hspi_tx_desc *tx_desc;
    struct tls_hostif_tx_msg     *tx_msg;
    struct tls_hostif *hif = tls_get_hostif();
    u32 cpu_sr;
    int err = 0;
    int offset;

    tx_desc = hspi->tls_slave_hspi->curr_tx_desc;

    hspi_tx_timeout_check(hspi, tx_desc); 

    while (!(tx_desc->valid_ctrl & BIT(31))) {
        tx_msg = dl_list_first(&hspi->tx_msg_pending_list,
                struct tls_hostif_tx_msg, list);
        if (tx_msg == NULL)
            break;

        switch (tx_msg->type) {
            case HOSTIF_TX_MSG_TYPE_EVENT:
            case HOSTIF_TX_MSG_TYPE_CMDRSP:
				if(tx_msg->u.msg_cmdrsp.buflen > HSPI_TXBUF_SIZE)
				{
					tx_msg->u.msg_cmdrsp.buflen = HSPI_TXBUF_SIZE;
				}
				MEMCPY((char *)tx_desc->buf_addr[0],
                        tx_msg->u.msg_cmdrsp.buf,
                        tx_msg->u.msg_cmdrsp.buflen);
                tls_mem_free(tx_msg->u.msg_cmdrsp.buf);
                tx_desc->buf_info = (tx_msg->u.msg_cmdrsp.buflen) << 12;

                cpu_sr = tls_os_set_critical();
                dl_list_del(&tx_msg->list);
                dl_list_add_tail(&hif->tx_event_msg_list, &tx_msg->list);
                tls_os_release_critical(cpu_sr);
                tx_desc->valid_ctrl = (1UL<<31);
                tls_reg_write32(HR_SDIO_RXEN, 0x01);                
                break;

            case HOSTIF_TX_MSG_TYPE_UDP:
            case HOSTIF_TX_MSG_TYPE_TCP:
                offset = hspi_socket_recv(hspi, tx_desc, tx_msg);
                if (offset == 0) {
                    cpu_sr = tls_os_set_critical();
                    dl_list_del(&tx_msg->list);
                    dl_list_add_tail(&hif->tx_msg_list, &tx_msg->list);
                    tls_os_release_critical(cpu_sr); 
                }
                break;

            default:
                /* cant go here */
                err = -1;
                break;
        }
        if (!err) {
            tx_desc = (struct tls_hspi_tx_desc *)tx_desc->next_desc_addr;
            hspi->tls_slave_hspi->curr_tx_desc = tx_desc; 
        }
    }

    return err;
}

void tls_hspi_tx_task(void *data)
{
    u8 err;
    struct tls_hspi *hspi = (struct tls_hspi *)data;

    for (;;) {
        err = tls_os_sem_acquire(hspi->tx_msg_sem, 0);
        if (err == TLS_OS_SUCCESS) {
    	       hspi_tx(hspi);
        } else {
            TLS_DBGPRT_ERR("hspi_tx_task acquire semaphore, "
                    "error type %d", err);
        }
    }
}

static int hspi_net_send(struct tls_hspi *hspi, 
        struct tls_hspi_rx_desc *rx_desc)
{
    struct tls_hostif_hdr *hdr;
    struct tls_hostif_socket_info skt_info;
    struct tls_hostif_ricmd_ext_hdr    *ext_hdr;
    //struct tls_hostif_cmd_hdr *cmd_hdr;
    int socket_num;
    u8  dest_type;
    u32 buflen;
    char *buf;

    //TLS_DBGPRT_INFO("----------->\n");

    hdr = (struct tls_hostif_hdr *)rx_desc->buf_addr;
    if (hdr->type != 0x0)
        return -1;

    buflen = be_to_host16(hdr->length);
    if (buflen > (HSPI_RXBUF_SIZE - sizeof(struct tls_hostif_hdr)))
        return -1;

    socket_num = hdr->dest_addr & 0x3F;
    dest_type = (hdr->dest_addr & 0xC0) >> 6;

    skt_info.socket = socket_num;
    skt_info.proto = dest_type;
    if (dest_type == 1) {
        /* udp */
        ext_hdr = (struct tls_hostif_ricmd_ext_hdr *)((char *)rx_desc->buf_addr +
                sizeof(struct tls_hostif_hdr));
        skt_info.remote_ip = ext_hdr->remote_ip;
        skt_info.remote_port = ext_hdr->remote_port;
        skt_info.local_port = ext_hdr->local_port; 
        skt_info.socket = 0;
        buf = (char *)ext_hdr + sizeof(struct tls_hostif_ricmd_ext_hdr);
    } else {
        buf = (char *)((char *)rx_desc->buf_addr + 
                sizeof(struct tls_hostif_hdr)); 
    } 

    tls_hostif_send_data(&skt_info, buf, buflen);

    return 0; 
}

static int hspi_rx_data(struct tls_hspi *hspi)
{
    struct tls_hspi_rx_desc *rx_desc;

    /* get rx descriptor */
    rx_desc = hspi->tls_slave_hspi->curr_rx_desc; 

    while(!(rx_desc->valid_ctrl & BIT(31))) {
        /* transmit data to lwip stack */
        hspi_net_send(hspi, rx_desc);

	// hspi_free_rxdesc(rx_desc);
	 rx_desc->valid_ctrl = BIT(31);
    /* 设置hspi/sdio tx enable寄存器，让sdio硬件知道有可用的tx descriptor */
    	 tls_reg_write32(HR_SDIO_TXEN, BIT(0));

        rx_desc = (struct tls_hspi_rx_desc *)rx_desc->next_desc_addr;
        hspi->tls_slave_hspi->curr_rx_desc = rx_desc; 
    }

    return 0;

}

void tls_hspi_rx_task(void *data)
{
    struct tls_hspi *hspi = (struct tls_hspi *)data;
    struct tls_hostif_hdr *hdr;
    u8 err;
    u32 *msg ;
    u8  *buf;
    u16   len, type;

    for (;;) {
        err = tls_os_queue_receive(hspi->rx_msg_queue, (void **)&msg, 0, 0);
        if (!err) {
            switch((u32)msg) {
                case HSPI_RX_CMD_MSG:
                    /* get command from HSPI RX CMD buffer */
                    buf = (u8 *)SDIO_CMD_RXBUF_ADDR;

                    err = tls_hostif_hdr_check(buf, SDIO_CMD_RXBUF_SIZE);
                    if (!err) {
                        hdr = (struct tls_hostif_hdr *)buf;
                        if (hdr->type == 0x1)
                            type = HOSTIF_HSPI_RI_CMD;
                        else if (hdr->type == 0x2)
                            type = HOSTIF_HSPI_AT_CMD;
                        else {
                            /* enable command buffer */
                            tls_reg_write32(HR_SDIO_DOWNCMDVALID, 0x1);	
                            break;
                        }
                        len = hdr->length;
                        tls_hostif_cmd_handler( type, (char *)buf, len);
                    } else {
                        //TODO:
                    }

                    /* enable command buffer */
                    tls_reg_write32(HR_SDIO_DOWNCMDVALID, 0x1);	
                    break;
                case HSPI_RX_DATA_MSG:
                    hspi_rx_data(hspi);
                    break;
                default:
                    break;
            }
        } else {
            TLS_DBGPRT_INFO("err = %d\n", err); 
        }
    }
}

#if TLS_CONFIG_TLS_DEBUG
static void tls_hspi_ram_info_dump(void)
{
    TLS_DBGPRT_INFO("HSPI_TXBUF_BASE_ADDR       : 0x%x -- 0x%x \n",
            HSPI_TXBUF_BASE_ADDR, HSPI_TX_DESC_BASE_ADDR - 1);
    TLS_DBGPRT_INFO("HSPI_TX_DESC_BASE_ADDR     : 0x%x -- 0x%x \n",
            HSPI_TX_DESC_BASE_ADDR, HSPI_RXBUF_BASE_ADDR - 1);
    TLS_DBGPRT_INFO("HSPI_RXBUF_BASE_ADDR       : 0x%x -- 0x%x \n",
            HSPI_RXBUF_BASE_ADDR, HSPI_RX_DESC_BASE_ADDR - 1);
    TLS_DBGPRT_INFO("HSPI_RX_DESC_BASE_ADDR     : 0x%x -- 0x%x \n",
            HSPI_RX_DESC_BASE_ADDR, 
            HSPI_RX_DESC_BASE_ADDR + HSPI_RX_DESC_TOTAL_SIZE);
}
#endif

static s16 tls_hspi_rx_cmd_cb(char *buf)
{
	struct tls_hspi *hspi = &g_hspi;
	 
	if(hspi->rx_msg_queue)
		tls_os_queue_send(hspi->rx_msg_queue, (void *)HSPI_RX_CMD_MSG, 0);
	return WM_SUCCESS;
}

static s16 tls_hspi_rx_data_cb(char *buf)
{
	struct tls_hspi *hspi = &g_hspi;

	if(hspi->rx_msg_queue)
		tls_os_queue_send(hspi->rx_msg_queue, (void *)HSPI_RX_DATA_MSG, 0);
	return WM_SUCCESS;
}

static s16 tls_hspi_tx_data_cb(char *buf)
{
	struct tls_hspi *hspi = &g_hspi;
	
	if(hspi->tx_msg_sem)
		tls_os_sem_release(hspi->tx_msg_sem);
	return WM_SUCCESS;
}

static void hspi_send_tx_msg(u8 hostif_mode, struct tls_hostif_tx_msg *tx_msg, bool is_event)
{
    u32 cpu_sr;
    switch (hostif_mode) {
        case HOSTIF_MODE_HSPI:
            if(tx_msg != NULL)
            {
                cpu_sr = tls_os_set_critical();
                dl_list_add_tail(&g_hspi.tx_msg_pending_list, &tx_msg->list);
                tls_os_release_critical(cpu_sr);
            }
            tls_os_sem_release(g_hspi.tx_msg_sem); 
            break;
        default:
            break;
    }
}

int tls_hspi_init(void)
{
    struct tls_hspi *hspi;
    char *stk;
    int err;
    void *rx_msg;
	struct tls_hostif *hif = tls_get_hostif();
	u8 mode;

	hspi = &g_hspi;
	memset(hspi, 0, sizeof(struct tls_hspi));

	tls_param_get(TLS_PARAM_ID_USRINTF, &mode, true);
	tls_slave_spi_init(mode);
	hspi->tls_slave_hspi = &g_slave_hspi;

	tls_hspi_rx_cmd_register(tls_hspi_rx_cmd_cb);
	tls_hspi_rx_data_register(tls_hspi_rx_data_cb);
	tls_hspi_tx_data_register(tls_hspi_tx_data_cb);
	
	dl_list_init(&hspi->tx_msg_pending_list);
	tls_os_sem_create(&hspi->tx_msg_sem, 0);
	hif->hspi_send_tx_msg_callback = hspi_send_tx_msg;

#if TLS_CONFIG_TLS_DEBUG
    tls_hspi_ram_info_dump();
#endif

    /* create rx messge queue */
#define HSPI_RX_MSG_SIZE     20
    rx_msg  = tls_mem_alloc(HSPI_RX_MSG_SIZE * sizeof(void *));
    if (!rx_msg)
        return WM_FAILED;

    err = tls_os_queue_create(&hspi->rx_msg_queue,
            rx_msg,
            HSPI_RX_MSG_SIZE, 0);
    if (err)
        return WM_FAILED;

    /* create hspi rx task */
    stk = tls_mem_alloc(HSPI_RX_TASK_STK_SIZE * sizeof(u32));
    if (!stk)
        return WM_FAILED;
    memset(stk, 0, HSPI_RX_TASK_STK_SIZE * sizeof(u32));
    tls_os_task_create(NULL, NULL,
            tls_hspi_rx_task,
            (void *)hspi,
            (void *)stk,          /* 任务栈的起始地址 */
            HSPI_RX_TASK_STK_SIZE * sizeof(u32), /* 任务栈的大小     */
            TLS_HSPI_RX_TASK_PRIO,
            0);
    /* create hspi tx task */
    stk = tls_mem_alloc(HSPI_TX_TASK_STK_SIZE * sizeof(u32));
    if (!stk)
        return WM_FAILED;
    memset(stk, 0, HSPI_TX_TASK_STK_SIZE * sizeof(u32));
    tls_os_task_create(NULL, NULL,
            tls_hspi_tx_task,
            (void *)hspi,
            (void *)stk,          /* 任务栈的起始地址 */
            HSPI_TX_TASK_STK_SIZE * sizeof(u32), /* 任务栈的大小     */
            TLS_HSPI_TX_TASK_PRIO,
            0);
    
    tls_hostif_set_net_status_callback();
    tls_hostif_send_event_init_cmplt();
    return WM_SUCCESS; 
}


#endif
