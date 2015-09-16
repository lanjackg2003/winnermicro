
/**************************************************************************
 * File Name                   : wm_cmdp_hostif.c
 * Author                       :
 * Version                      :
 * Date                          :
 * Description                 :
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd. 
 * All rights reserved.
 *
 ***************************************************************************/
#if (GCC_COMPILE==1)
#include "wm_cmdp_hostif_gcc.h"
#else
#include "wm_cmdp_hostif.h"
#endif
#include "wm_debug.h"
#include "wm_hspi.h"
#include "list.h"
#include "wm_mem.h"
#include "wm_regs.h"
#include "wm_params.h"
#include <string.h>
#include <ctype.h>

#if TLS_CONFIG_HOSTIF
#include "wm_cmdp_ri.h"
#include "wm_cmdp_at.h"
/* data msg */
struct tls_hostif_tx_msg       g_hostif_tx_msg[HOSTIF_TX_MSG_NUM];
/* event, cmdrsp msg */
struct tls_hostif_tx_msg       g_hostif_tx_event_msg[HOSTIF_TX_EVENT_MSG_NUM];

struct tls_hostif g_hostif;
struct tls_hostif *tls_get_hostif(void)
{
	return &g_hostif;
}

u8 default_socket = 0;

struct tls_uart_circ_buf * sockrecvmit[TLS_MAX_NETCONN_NUM];

struct tls_uart_circ_buf * tls_hostif_get_recvmit(int socket_num)
{
	TLS_DBGPRT_INFO("socket_num=%d, precvmit=0x%x\n", socket_num, sockrecvmit[socket_num-1]);
	return sockrecvmit[socket_num-1];
}

static void tls_hostif_set_recvmit(int socket_num, struct tls_uart_circ_buf * precvmit)
{
	TLS_DBGPRT_INFO("socket_num=%d, precvmit=0x%x\n",socket_num, precvmit);
	sockrecvmit[socket_num-1] = precvmit;
}
	
static void alloc_recvmit(int socket_num)
{
	char * buf;
	struct tls_uart_circ_buf * precvmit = tls_hostif_get_recvmit(socket_num);
	if(precvmit != NULL)
		return;
	precvmit = tls_mem_alloc(sizeof(struct tls_uart_circ_buf));
	if(precvmit == NULL)
		return;
	memset(precvmit, 0, sizeof(struct tls_uart_circ_buf));
	buf = tls_mem_alloc(TLS_SOCKET_RECV_BUF_SIZE);
	if(buf == NULL)
	{
		tls_mem_free(precvmit);
		precvmit = NULL;
		tls_hostif_set_recvmit(socket_num, precvmit);
		return;
	}
	precvmit->buf = (u8 *)buf;
	tls_hostif_set_recvmit(socket_num, precvmit);
}

static void free_recvmit(int socket_num)
{
	struct tls_uart_circ_buf * precvmit = tls_hostif_get_recvmit(socket_num);
	if(precvmit == NULL)
		return;
	if(precvmit->buf != NULL)
		tls_mem_free(precvmit->buf);
	tls_mem_free(precvmit);
	precvmit = NULL;
	tls_hostif_set_recvmit(socket_num, precvmit);
}

void tls_hostif_fill_cmdrsp_hdr(struct tls_hostif_cmdrsp *cmdrsp,
        u8 code, u8 err, u8 ext)
{
    cmdrsp->cmd_hdr.code = code;
    cmdrsp->cmd_hdr.err = err;
    cmdrsp->cmd_hdr.ext = ext;
    cmdrsp->cmd_hdr.msg_type = HOSTIF_MSG_TYPE_RSP;
}

void tls_hostif_fill_event_hdr(struct tls_hostif_event *event,
        u8 code, u8 err, u8 ext)
{
    event->cmd_hdr.code = code;
    event->cmd_hdr.err = err;
    event->cmd_hdr.ext = ext;
    event->cmd_hdr.msg_type = HOSTIF_MSG_TYPE_EVENT; 
}

void tls_hostif_fill_hdr(struct tls_hostif *hif,
        struct tls_hostif_hdr *hdr,
        u8 type, u16 length, u8 flag, u8 dest_addr, u8 chk)
{
    hdr->sync = 0xAA;
    hdr->type = type;
    hdr->length = host_to_be16(length);
    hdr->seq_num = hif->hspi_tx_seq++;
    hdr->flag = flag;
    hdr->dest_addr = dest_addr;
    hdr->chk = chk;
}

struct tls_hostif_tx_msg *tls_hostif_get_tx_event_msg(struct tls_hostif *hif)
{
    u32 cpu_sr;
    struct tls_hostif_tx_msg *tx_msg;

    cpu_sr = tls_os_set_critical();
    if (dl_list_empty(&hif->tx_event_msg_list)) {
        tx_msg = NULL;
    } else {
        tx_msg = dl_list_first(&hif->tx_event_msg_list,
                struct tls_hostif_tx_msg, list);
        dl_list_del(&tx_msg->list);
    }
    tls_os_release_critical(cpu_sr); 

    return tx_msg; 
}

struct tls_hostif_tx_msg *tls_hostif_get_tx_msg(void)
{
    u32 cpu_sr;
    struct tls_hostif_tx_msg *tx_msg;

    cpu_sr = tls_os_set_critical();
    if (dl_list_empty(&g_hostif.tx_msg_list)) {
        tx_msg = NULL;
    } else {
        tx_msg = dl_list_first(&g_hostif.tx_msg_list,
                struct tls_hostif_tx_msg, list);
        dl_list_del(&tx_msg->list);
    }
    tls_os_release_critical(cpu_sr); 

    return tx_msg; 
}

int tls_hostif_atcmd_loopback(u8 hostif_type,
        char *buf, u32 buflen)
{
    struct tls_hostif_tx_msg *tx_msg;
    struct tls_hostif *hif = tls_get_hostif();
    

    if (buf == NULL || buflen == 0)
        return -1;

    switch (hostif_type) {
        case HOSTIF_MODE_UART0:
            tx_msg = tls_hostif_get_tx_event_msg(hif);
            if (tx_msg == NULL)
                return -1;

            tx_msg->offset = 0;
            tx_msg->u.msg_cmdrsp.buf = buf;
            tx_msg->type = HOSTIF_TX_MSG_TYPE_CMDRSP;
            tx_msg->u.msg_cmdrsp.buflen = buflen;

            if(hif->uart_send_tx_msg_callback != NULL)
                hif->uart_send_tx_msg_callback(hostif_type, tx_msg, FALSE);
            break;
        case HOSTIF_MODE_UART1_LS:
            tx_msg = tls_hostif_get_tx_event_msg(hif);
            if (tx_msg == NULL)
                return -1;

            tx_msg->offset = 0;
            tx_msg->u.msg_cmdrsp.buf = buf;
            tx_msg->type = HOSTIF_TX_MSG_TYPE_CMDRSP;
            tx_msg->u.msg_cmdrsp.buflen = buflen;

            if(hif->uart_send_tx_msg_callback != NULL)
                hif->uart_send_tx_msg_callback(hostif_type, tx_msg, FALSE);
            break;
        default:
            break;
    }
    return 0; 
}

int tls_hostif_process_cmdrsp(u8 hostif_type, char *cmdrsp, u32 cmdrsp_size)
{
    struct tls_hostif_tx_msg *tx_msg;
    struct tls_hostif *hif = tls_get_hostif();
    

    //TLS_DBGPRT_INFO("===>\n");
    //printf("**\n");

    if (cmdrsp == NULL || cmdrsp_size == 0)
        return -1;

    switch (hostif_type) 
	{
        case HOSTIF_MODE_HSPI:
            tx_msg = tls_hostif_get_tx_event_msg(hif);
            if (tx_msg == NULL)
            {
                return -1;
            }
            tx_msg->offset = 0;
            tx_msg->u.msg_cmdrsp.buf = cmdrsp;
            tx_msg->type = HOSTIF_TX_MSG_TYPE_CMDRSP;
            tx_msg->u.msg_cmdrsp.buflen = cmdrsp_size;
            if(hif->hspi_send_tx_msg_callback != NULL)
            {
                hif->hspi_send_tx_msg_callback(hostif_type, tx_msg, FALSE);
            }
            break;
        case HOSTIF_MODE_UART0:
            tx_msg = tls_hostif_get_tx_event_msg(hif);
            if (tx_msg == NULL) 
			{
                TLS_DBGPRT_ERR("event msg is not avaible \n");
                return -1;
            }
            tx_msg->offset = 0;
            tx_msg->u.msg_cmdrsp.buf = cmdrsp;
            tx_msg->type = HOSTIF_TX_MSG_TYPE_CMDRSP;
            tx_msg->u.msg_cmdrsp.buflen = cmdrsp_size;

            if(hif->uart_send_tx_msg_callback != NULL)
                hif->uart_send_tx_msg_callback(hostif_type, tx_msg, FALSE);
            break;
        case HOSTIF_MODE_UART1_LS:
        case HOSTIF_MODE_UART1_HS:
            tx_msg = tls_hostif_get_tx_event_msg(hif);
            if (tx_msg == NULL)
                return -1;

            tx_msg->offset = 0;
            tx_msg->u.msg_cmdrsp.buf = cmdrsp;
            tx_msg->type = HOSTIF_TX_MSG_TYPE_CMDRSP;
            tx_msg->u.msg_cmdrsp.buflen = cmdrsp_size;

            if(hif->uart_send_tx_msg_callback != NULL)
                hif->uart_send_tx_msg_callback(hostif_type, tx_msg, FALSE);
            break;
        default:
            break;
    }
    return 0;
}

int tls_hostif_cmd_handler(u8 hostif_cmd_type, char *buf, u32 length)
{
#if TLS_CONFIG_AP
#define CMD_RSP_BUF_SIZE    512
#else
#define CMD_RSP_BUF_SIZE    256
#endif
    char *cmdrsp_buf;
    u32 cmdrsp_size;
    struct tls_atcmd_token_t atcmd_tok;
    int err;
    int i, name_len;
    struct tls_hostif_hdr *hdr = (struct tls_hostif_hdr *)buf;
    u8 hostif_type;
	struct tls_hostif *hif = tls_get_hostif();

    //TLS_DBGPRT_INFO("===>\n");
    cmdrsp_size = CMD_RSP_BUF_SIZE;

    switch (hostif_cmd_type) {
        case HOSTIF_HSPI_RI_CMD:
        case HOSTIF_UART1_RI_CMD:
            cmdrsp_buf = tls_mem_alloc(CMD_RSP_BUF_SIZE);
            if (!cmdrsp_buf)
                return -1;
            err = tls_ricmd_exec(buf + sizeof(struct tls_hostif_hdr), 
                    be_to_host16(hdr->length), cmdrsp_buf, &cmdrsp_size);
            tls_hostif_fill_hdr(hif, 
                    (struct tls_hostif_hdr *)cmdrsp_buf,
                    PACKET_TYPE_RI_CMD,
                    cmdrsp_size, 0, 0, 0); 
            cmdrsp_size += sizeof(struct tls_hostif_hdr);
            if (hostif_cmd_type == HOSTIF_HSPI_RI_CMD)
                hostif_type = HOSTIF_MODE_HSPI;
            else
                hostif_type = HOSTIF_MODE_UART1_HS;
            break;
        case HOSTIF_HSPI_AT_CMD:

            memset(&atcmd_tok, 0, sizeof(struct tls_atcmd_token_t));
            err = tls_atcmd_parse(&atcmd_tok, buf + sizeof(struct tls_hostif_hdr),
                    length); 

            if (err) {
                //TODO:
            }
            cmdrsp_buf = tls_mem_alloc(CMD_RSP_BUF_SIZE);
            if (!cmdrsp_buf)
                return -1;

            err = tls_atcmd_exec(&atcmd_tok, cmdrsp_buf, &cmdrsp_size);
            if (err) {
                //TODO:
            }
            hostif_type = HOSTIF_MODE_HSPI;

            break;
        case HOSTIF_UART1_AT_CMD:
        case HOSTIF_UART0_AT_CMD:
            if (hostif_cmd_type == HOSTIF_UART1_AT_CMD)
                hostif_type = HOSTIF_MODE_UART1_LS;
            else
                hostif_type = HOSTIF_MODE_UART0;

            /* at cmd loopback */
            if (hif->uart_insdisp) {
                u8 *atcmd_loopback_buf = tls_mem_alloc(length+1);
                if (!atcmd_loopback_buf)
                    return -1;
                MEMCPY(atcmd_loopback_buf, buf, length);
                atcmd_loopback_buf[length-1] = '\r';
                atcmd_loopback_buf[length] = '\n';
                err = tls_hostif_atcmd_loopback(hostif_type,
                        (char *)atcmd_loopback_buf, length+1);
                if (err)
                    tls_mem_free(atcmd_loopback_buf);
            }

            cmdrsp_buf = tls_mem_alloc(CMD_RSP_BUF_SIZE);
            if (!cmdrsp_buf)
                return -1;
            memset(&atcmd_tok, 0, sizeof(struct tls_atcmd_token_t));
            if (hostif_cmd_type == HOSTIF_UART0_AT_CMD)
                atcmd_tok.cmd_mode = CMD_MODE_UART0_ATCMD;
            else
                atcmd_tok.cmd_mode = CMD_MODE_UART1_ATCMD;
            //TLS_DBGPRT_DUMP(buf, length);
            //TLS_DBGPRT_INFO("at cmd :%s\n", buf);
            err = tls_atcmd_parse(&atcmd_tok, buf+3, length - 3); 


#if 0
            TLS_DBGPRT_INFO("atcmd = %s\n", atcmd_tok.name);
            TLS_DBGPRT_INFO("atcmd_tok: argc = %d, op = %d \n", 
                    atcmd_tok.arg_found,
                    atcmd_tok.op);
            for (i=0;i<atcmd_tok.arg_found;i++)
                TLS_DBGPRT_INFO("argv[%d] length = %d\n", i,
                        atcmd_tok.arg[i+1] - atcmd_tok.arg[i] - 1);
#endif

            if (err) {
                TLS_DBGPRT_INFO("err parse cmd, code = %d\n", err);
                cmdrsp_size = sprintf(cmdrsp_buf, "+ERR=%d\r\n", err);
            } else {
                name_len = strlen(atcmd_tok.name);
                for (i = 0; i < name_len; i++)
                    atcmd_tok.name[i] = toupper(atcmd_tok.name[i]);
                cmdrsp_size = CMD_RSP_BUF_SIZE;
                err = tls_atcmd_exec(&atcmd_tok, cmdrsp_buf, &cmdrsp_size);
                if (err) {
                    //TODO:
                } 	
                /* TODO: send cmd response */		
                cmdrsp_buf[cmdrsp_size] = '\r';
                cmdrsp_buf[cmdrsp_size+1] = '\n';
		  cmdrsp_buf[cmdrsp_size+2] = '\r';
                cmdrsp_buf[cmdrsp_size+3] = '\n';
                cmdrsp_buf[cmdrsp_size+4] = '\0';
                cmdrsp_size += 4;
                TLS_DBGPRT_INFO("at response: 0x%x, %s\n", cmdrsp_buf, cmdrsp_buf);
                //tls_mem_free(cmdrsp_buf);
            }
            break;
        default:
            TLS_DBGPRT_ERR("illegal command type\n");
			return -1;
            //break;
    }

    err = tls_hostif_process_cmdrsp(hostif_type, cmdrsp_buf, cmdrsp_size);
    if (err)
        tls_mem_free(cmdrsp_buf);

    return 0;

}

int tls_hostif_hdr_check(u8 *buf, u32 length)
{
    if (!buf)
        return -1;

#if 0

    hdr = (struct tls_hostif_hdr *)buf;
    payload_len = be_to_host16(*(u16 __packed *)hdr->length);
    chksum = hdr->flag & 0x1;
    type = hdr->type;

    if (payload_len != (length - sizeof(struct tls_hostif_hdr))) {
        return -1;
    }
    /* check comand type */
    if (type > HOSTCMD_TYPE_AT_CMD) 
        return -1;
#endif

    //TODO: 计算校验和并比较 
    //

    return 0;
}

int tls_hostif_send_event_port_check(void)
{
    struct tls_hostif *hif = tls_get_hostif();

    if (hif->hostif_mode == HOSTIF_MODE_UART1_HS) {
        return 0; 
    } 
    if (hif->hostif_mode == HOSTIF_MODE_HSPI) {
        return 0;
    }

    return -1;
}

int tls_hostif_send_event(char *buf, u32 buflen, u8 type)
{
    struct tls_hostif_tx_msg *tx_msg;
    struct tls_hostif *hif = tls_get_hostif();
    u8 ext;
    struct tls_hostif_event *event = (struct tls_hostif_event *)buf;

    tx_msg = tls_hostif_get_tx_event_msg(hif); 
    if (!tx_msg) {
        return -1;
    }

    tls_hostif_fill_hdr(hif, &event->hdr,
            PACKET_TYPE_RI_CMD,
            buflen - 8, 0, 0, 0); 
    if (buflen == 12)
        ext = 0;
    else {
        ext = 1;
    }
    tls_hostif_fill_event_hdr(event, type, 0, ext); 

    tx_msg->u.msg_event.buf = buf;
    tx_msg->u.msg_event.buflen = buflen;
    tx_msg->type = HOSTIF_TX_MSG_TYPE_EVENT;

    //TLS_DBGPRT_DUMP(buf, buflen);

    if (hif->hostif_mode == HOSTIF_MODE_HSPI) {
        if(hif->hspi_send_tx_msg_callback != NULL)
            hif->hspi_send_tx_msg_callback(HOSTIF_MODE_HSPI, tx_msg, TRUE);
    }
    else if (hif->hostif_mode == HOSTIF_MODE_UART1_HS) {
        if(hif->uart_send_tx_msg_callback != NULL)
            hif->uart_send_tx_msg_callback(HOSTIF_MODE_UART1_HS, tx_msg, TRUE);
    } else {
        return -1;
    }
    return 0;
}

int tls_hostif_send_event_init_cmplt(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;

    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr);
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_INIT_END); 

    if (err)
        tls_mem_free(buf);

    return 0;
}

static int tls_hostif_send_event_linkup(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr);
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_LINKUP); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_wjoin_success(void)
{
    char *buf;
    u16 buflen;
    int err;
    char *p;
	struct tls_curr_bss_t bss;


    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;

	tls_wifi_get_current_bss(&bss);
	
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr) + 12 + bss.ssid_len;
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    p = &buf[12];
    *p++ = 1;


    MEMCPY(p, bss.bssid, ETH_ALEN);
    p += ETH_ALEN;
    *p++ = (char)bss.type;
    *p++ = (char)bss.channel;
    *p++ = (char)bss.encryptype;
    *p++ = (char)bss.ssid_len;
    MEMCPY(p, bss.ssid, bss.ssid_len);
    p += bss.ssid_len;
	*p = bss.rssi;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_JOIN_RES); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_wjoin_failed(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr) + 1;
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    buf[12] = 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_JOIN_RES); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_linkdown(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr);
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_LINKDOWN); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_sta_join(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr);
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_STA_JOIN); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_sta_leave(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr);
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_STA_LEAVE); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_crc_err(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr);
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_CRC_ERR); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_tx_fail(void)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr);
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_TX_ERR); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_tcp_conn(
        u8 socket, u8 res)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr) + 2;
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;
    buf[12] = socket;
    buf[13] = res;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_TCP_CONN); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_tcp_join(u8 socket)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr) + 1;
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;
    buf[12] = socket;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_TCP_JOIN); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_tcp_dis(u8 socket)
{
    char *buf;
    u16 buflen;
    int err;

    err = tls_hostif_send_event_port_check();
    if (err)
        return 0;
    buflen = sizeof(struct tls_hostif_hdr) +
        sizeof(struct tls_hostif_cmd_hdr) + 1;
    buf = (char *)tls_mem_alloc(buflen);
    if (!buf)
        return 0;
    buf[12] = socket;

    err = tls_hostif_send_event(buf, buflen,
            HOSTIF_EVENT_TCP_DIS); 
    if (err)
        tls_mem_free(buf);

    return 0;
}

int tls_hostif_send_event_scan_cmplt(struct tls_scan_bss_t *scan_res,
        enum tls_cmd_mode cmd_mode)
{
    char *buf;
    u32 buflen, remain_len;
    int err = 0; 
    int i, j;
    struct tls_bss_info_t *bss_info;
    char *p;
    u8 hostif_type;
    u32 strlen;

    if (scan_res == NULL)
        return -1;

    switch (cmd_mode) {
        case CMD_MODE_HSPI_RICMD:
        case CMD_MODE_UART1_RICMD:
            buflen = 1450; 
            buf = (char *)tls_mem_alloc(buflen);
            if (!buf)
                return 0;
            if (scan_res->count == 0) {
                buflen = 13;
                p = buf + 12;
                *p++ = 0;
            }
            else {
                remain_len = buflen;
                p = buf + 12;
                buflen = 12;
                remain_len -= 12;
                *p++ = (u8)scan_res->count;
                remain_len--;
                buflen++;
                bss_info = scan_res->bss;
                for (i = 0; i < scan_res->count; i++) {
                    if (remain_len < 43)
                        break;
                    MEMCPY(p, bss_info->bssid, ETH_ALEN);
                    p += ETH_ALEN;
                    *p++ = bss_info->mode;
                    *p++ = bss_info->channel;
                    *p++ = bss_info->privacy;
                    *p++ = bss_info->ssid_len;
                    MEMCPY(p, bss_info->ssid, bss_info->ssid_len);
                    p += bss_info->ssid_len;
                    *p++ = (char)(0x100-bss_info->rssi);
                    buflen += (11 + bss_info->ssid_len);
                    remain_len = remain_len - (11 + bss_info->ssid_len);
                    bss_info++; 
                }
            }

            err = tls_hostif_send_event(buf, buflen,
                    HOSTIF_EVENT_SCAN_RES); 
            break;
        case CMD_MODE_UART0_ATCMD:
        case CMD_MODE_UART1_ATCMD:
            buf = (char *)tls_mem_alloc(2500);
            if (!buf)
                return 0;
            buflen = sprintf(buf, "+OK=");
            p = buf + buflen;
            bss_info = scan_res->bss;
            for (i = 0; i < scan_res->count; i++) {
                strlen = sprintf(p, "%02X%02X%02X%02X%02X%02X,%u,%u,%u,\"",
                        bss_info->bssid[0], bss_info->bssid[1], bss_info->bssid[2],
                        bss_info->bssid[3], bss_info->bssid[4], bss_info->bssid[5],
                        bss_info->mode, bss_info->channel, bss_info->privacy);
                buflen += strlen;
                p = buf + buflen;
                for (j = 0; j < bss_info->ssid_len; j++) {
                    strlen = sprintf(p, "%c", bss_info->ssid[j]);
                    buflen += strlen;
                    p = buf + buflen;
                }
                strlen = sprintf(p, "\",%u\r\n", (char)(0x100-bss_info->rssi));
                buflen += strlen;
                p = buf + buflen;
                bss_info++; 
            } 
            if (cmd_mode == CMD_MODE_UART0_ATCMD)
                hostif_type = HOSTIF_MODE_UART0;
            else
                hostif_type = HOSTIF_MODE_UART1_LS;

            err = tls_hostif_process_cmdrsp(hostif_type, buf, buflen);

            break;
        default:
            break;
    }
    if (err && buf)
        tls_mem_free(buf);

    return 0; 
}

void tls_hostif_tx_timeout(void *ptmr, void *parg)
{
    struct tls_hostif *hif = (struct tls_hostif *)parg;

    if (hif->hostif_mode == HOSTIF_MODE_HSPI)
        if(hif->uart_send_tx_msg_callback != NULL)
            hif->uart_send_tx_msg_callback(HOSTIF_MODE_HSPI, NULL, FALSE);
    else if (hif->hostif_mode == HOSTIF_MODE_UART0) {
        if(hif->uart_send_tx_msg_callback != NULL)
            hif->uart_send_tx_msg_callback(HOSTIF_MODE_UART0, NULL, FALSE);
    } else if ((hif->hostif_mode == HOSTIF_MODE_UART1_LS) ||
                (hif->hostif_mode == HOSTIF_MODE_UART1_HS)) {
        if(hif->uart_send_tx_msg_callback != NULL)
            hif->uart_send_tx_msg_callback(hif->hostif_mode, NULL, FALSE);
    } else 
        ;
}

static void hostif_wscan_cmplt(void)
{
    char *buf;
    u32 buflen;
    int err;    
    enum tls_cmd_mode cmd_mode;
    struct tls_hostif *hif = tls_get_hostif();

    if (hif->last_scan) {

        cmd_mode = hif->last_scan_cmd_mode;
        hif->last_scan = 0; 

        buflen = 2000;
        buf = tls_mem_alloc(buflen);
        if (!buf)
            return;

        err = tls_wifi_get_scan_rslt((u8 *)buf, buflen);
        if (err) {
            tls_mem_free(buf);
            return;
        }
        switch (cmd_mode) {
            case CMD_MODE_HSPI_RICMD:
            case CMD_MODE_UART1_RICMD:
                tls_hostif_send_event_scan_cmplt((struct tls_scan_bss_t *)buf, cmd_mode);
                tls_mem_free(buf); 
                break;
            case CMD_MODE_UART0_ATCMD:
            case CMD_MODE_UART1_ATCMD:
                tls_hostif_send_event_scan_cmplt((struct tls_scan_bss_t *)buf, cmd_mode);
                tls_mem_free(buf); 
                tls_os_sem_release(hif->uart_atcmd_sem); 
                break;
            default:
                tls_mem_free(buf);
        }
    } 
}

int tls_hostif_init(void)
{
    struct tls_hostif *hif;
    struct tls_hostif_tx_msg *tx_msg;
    int i;
    int err;

	u16 transparent_trigger_length;
	u8 mode;

    hif= &g_hostif;
    memset(hif, 0, sizeof(struct tls_hostif));
    tls_param_get(TLS_PARAM_ID_AUTO_TRIGGER_LENGTH, &transparent_trigger_length, FALSE);
    hif->uart_atlt = transparent_trigger_length;

    dl_list_init(&hif->tx_msg_list);
    dl_list_init(&hif->tx_event_msg_list);

    /* initialize tx message resouce pool */
    for (i = 0; i < HOSTIF_TX_MSG_NUM; i++) {
        tx_msg = &g_hostif_tx_msg[i];
        dl_list_add_tail(&hif->tx_msg_list, &tx_msg->list); 
    }

    for (i = 0; i < HOSTIF_TX_EVENT_MSG_NUM; i++) {
        tx_msg = &g_hostif_tx_event_msg[i];
        dl_list_add_tail(&hif->tx_event_msg_list, &tx_msg->list);
    }

	//cfg_param.user_port_mode = TLS_PARAM_USR_INTF_LUART; /*set default LUART MODE*/
	tls_param_get(TLS_PARAM_ID_USRINTF, (void *)&mode, TRUE);
    if ((mode == TLS_PARAM_USR_INTF_HSPI) 
		|| (mode == TLS_PARAM_USR_INTF_HSDIO)){
        hif->hostif_mode = HOSTIF_MODE_HSPI;
    }
    else if (mode == TLS_PARAM_USR_INTF_HUART)
        hif->hostif_mode = HOSTIF_MODE_UART1_HS;
    else if (mode == TLS_PARAM_USR_INTF_LUART)
        hif->hostif_mode = HOSTIF_MODE_UART1_LS;
    else
        hif->hostif_mode = HOSTIF_MODE_HSPI;

    err = tls_os_sem_create(&hif->uart_atcmd_sem, 0);
    if (err)
        return err;

    err = tls_os_timer_create(&hif->tx_timer,
            tls_hostif_tx_timeout,
            hif,
            60*HZ,  /* 60 seconds */
            true,
            NULL);

    if (!err)
        tls_os_timer_start(hif->tx_timer); 

    /* register scan complt callback*/
    tls_wifi_scan_result_cb_register(hostif_wscan_cmplt);

    return err; 
}

#if TLS_CONFIG_SOCKET_RAW
int tls_hostif_recv_data(struct tls_hostif_tx_msg *tx_msg) 
{
    struct tls_hostif *hif = &g_hostif;

    if (hif->hostif_mode == HOSTIF_MODE_UART0) {
        if(hif->uart_send_tx_msg_callback != NULL)
            hif->uart_send_tx_msg_callback(HOSTIF_MODE_UART0, tx_msg, FALSE);
    } else if ((hif->hostif_mode == HOSTIF_MODE_UART1_LS) ||
            (hif->hostif_mode == HOSTIF_MODE_UART1_HS)) {
        if(hif->uart_send_tx_msg_callback != NULL)
            hif->uart_send_tx_msg_callback(hif->hostif_mode, tx_msg, FALSE);
    } else {
        /* HSPI */
        if(hif->hspi_send_tx_msg_callback != NULL)
            hif->hspi_send_tx_msg_callback(HOSTIF_MODE_HSPI, tx_msg, FALSE);
    }

    return 0; 
}

int tls_hostif_send_data(struct tls_hostif_socket_info *skt_info, 
        char *buf, u32 buflen)
{
    int err = 0;
    if(skt_info->socket)
        err = tls_socket_send(skt_info->socket, buf, buflen);
    else if(skt_info->proto == 1)//udp
        err = tls_socket_udp_sendto(skt_info->local_port, (u8 *)(&skt_info->remote_ip), skt_info->remote_port, buf, buflen);
    
    return err;
}

static void hostif_default_socket_setup(void *ptmr, void *parg)
{
	tls_hostif_close_default_socket();/*自动工作模式，不断网再联网的话，会有内存泄露*/
	default_socket = 0;
	tls_hostif_create_default_socket();
}

static tls_os_timer_t *default_sock_tmr = NULL;
static void hostif_default_socket_create_tmr(int ticks)
{
    tls_os_status_t err;
    if(default_sock_tmr != NULL)
    {
        tls_os_timer_change(default_sock_tmr, ticks);
        return;
    }
    err = tls_os_timer_create(&default_sock_tmr,
            hostif_default_socket_setup,
            (void *)0,
            HZ/100,  /* 10 ms */
            false,
            NULL);

    if (!err)
        tls_os_timer_start(default_sock_tmr); 
}

static void hostif_default_socket_stop_tmr()
{
	if(default_sock_tmr != NULL)
	{
       	tls_os_timer_stop(default_sock_tmr); 
    	}
	tls_hostif_close_default_socket();
}

static void hostif_default_socket_err(u8 skt_num, err_t err)
{
	if (tls_cmd_get_auto_mode() && (default_socket == 0 || default_socket == skt_num)){
		if(default_sock_tmr != NULL)
		{
			tls_os_timer_change(default_sock_tmr, 10*HZ);
		}
	}
}

static err_t hostif_socket_rpt(u8 skt_num, u16 datalen, u8 *ipaddr, u16 port, err_t err)
{
	#undef CMDIND_BUF_SIZE
	#define CMDIND_BUF_SIZE 128
	char *cmdind_buf = NULL;
	int err1 = 0;
	u32 cmdind_size = 0;

	struct tls_hostif *hif = tls_get_hostif();

	if (hif->rptmode){		
		cmdind_buf = tls_mem_alloc(CMDIND_BUF_SIZE);
		if (cmdind_buf)
		{
			cmdind_size = sprintf(cmdind_buf,"+SKTRPT=%d,%d,%d,%d\r\n\r\n",skt_num, datalen, *((u32*)ipaddr),port);
			err1 = tls_hostif_process_cmdrsp(hif->hostif_mode, cmdind_buf, cmdind_size);
			if (err1)
			{
				tls_mem_free(cmdind_buf);
				cmdind_buf = NULL;
				return -1;
			}
			return 0;
		}
	}
	return -1;
}

static err_t  hostif_socket_recv(u8 skt_num, struct pbuf *p, err_t err)
{
    struct tls_hostif_tx_msg *tx_msg;
    u8 state;
    struct tls_skt_status_ext_t skt_ext;


    tx_msg = tls_hostif_get_tx_msg();
    err = tls_cmd_get_socket_state(skt_num, &state, &skt_ext);
    if (tx_msg == NULL || err) {
        pbuf_free(p);
        return ERR_OK;
    } else {
        tx_msg->type = HOSTIF_TX_MSG_TYPE_TCP;
        tx_msg->u.msg_tcp.p = p;
        tx_msg->u.msg_tcp.sock = skt_num;
        if(skt_ext.protocol == SOCKET_PROTO_UDP)
        {
            tx_msg->type = HOSTIF_TX_MSG_TYPE_UDP;
            tx_msg->u.msg_udp.p = p;
            tx_msg->u.msg_udp.sock = skt_num;
            tx_msg->u.msg_udp.port = skt_ext.remote_port;
            tx_msg->u.msg_udp.localport = skt_ext.local_port;
            MEMCPY(&tx_msg->u.msg_udp.ip_addr.addr, &skt_ext.host_ipaddr[0], 4);
        }
        tx_msg->offset = 0;
        tx_msg->time = tls_os_get_time();
    }
//TLS_DBGPRT_INFO("tx_msg->u.msg_tcp.p=0x%x\n", tx_msg->u.msg_tcp.p);
    tls_hostif_recv_data(tx_msg);
    return ERR_OK;
}

static void  hostif_default_socket_state_changed(u8 skt_num, u8 event, u8 state)
{
    //cmd_set_uart1_mode_callback callback;
    TLS_DBGPRT_INFO("event=%d, state=%d\n", event, state);
    switch (event) {
        case NET_EVENT_TCP_JOINED:
            alloc_recvmit(skt_num);
            break;
        case NET_EVENT_TCP_DISCONNECT:               
            free_recvmit(skt_num);
            break; 
        case NET_EVENT_TCP_CONNECTED:
            alloc_recvmit(skt_num);
            break;
        case NET_EVENT_TCP_CONNECT_FAILED:
            free_recvmit(skt_num);
            break;
        case NET_EVENT_UDP_START:
            alloc_recvmit(skt_num);
        default:
            break;
    }
    //callback = tls_cmd_get_set_uart1_mode();
    //if(callback!=NULL)
    //    callback(UART_TRANS_MODE);
}

struct tls_socket_desc skt_desc_def;
int tls_hostif_create_default_socket(void)
{
    int ret = 0;
    struct tls_socket_cfg *skt_cfg = tls_cmd_get_socket_cfg();
    if (tls_cmd_get_auto_mode()){	
		memset(&skt_desc_def, 0, sizeof(struct tls_socket_desc));
		skt_desc_def.cs_mode = skt_cfg->client ? SOCKET_CS_MODE_CLIENT : SOCKET_CS_MODE_SERVER;
		MEMCPY(skt_desc_def.ip_addr, skt_cfg->ip_addr, sizeof(struct ip_addr));
		skt_desc_def.localport = skt_cfg->port;
		skt_desc_def.port = skt_cfg->port;
		skt_desc_def.protocol = (enum tls_socket_protocol)skt_cfg->proto;
		skt_desc_def.timeout = skt_cfg->timeout;
		skt_desc_def.recvf = hostif_socket_recv;
		skt_desc_def.errf = hostif_default_socket_err;
		skt_desc_def.state_changed = hostif_default_socket_state_changed;
		if (default_socket == 0){
			ret = tls_socket_create(&skt_desc_def);
			if (ret < 0){
				//hostif_default_socket_setup((void *)0, (void *)0);
				hostif_default_socket_create_tmr(100);
			}else{
				TLS_DBGPRT_INFO("create socket:%d\n", ret);
				default_socket = ret;
			}
		}				
    }
	return ret;
}

int tls_hostif_close_default_socket(void)
{
	int ret = 0;
	
	if (tls_cmd_get_auto_mode()){
		if(default_socket > 0)
		{
	  	   	ret = tls_socket_close(default_socket);
			free_recvmit(default_socket);
	  		default_socket = 0;
		}
	}
	return ret;
}
static void  hostif_socket_state_changed_ATCMD(u8 skt_num, u8 event, u8 state)
{
    struct tls_hostif *hif = tls_get_hostif();
    TLS_DBGPRT_INFO("event=%d, state=%d\n", event, state);
    switch (event) {
        case NET_EVENT_TCP_JOINED:
            alloc_recvmit(skt_num);
            tls_hostif_send_event_tcp_join(skt_num);
            break;
        case NET_EVENT_TCP_DISCONNECT:               
            free_recvmit(skt_num);
            tls_hostif_send_event_tcp_dis(skt_num);
            break; 
        case NET_EVENT_TCP_CONNECTED:
            alloc_recvmit(skt_num);
            tls_os_sem_release(hif->uart_atcmd_sem);
            break;
        case NET_EVENT_TCP_CONNECT_FAILED:
            free_recvmit(skt_num);
            tls_os_sem_release(hif->uart_atcmd_sem);
            break;
        case NET_EVENT_UDP_START:
            alloc_recvmit(skt_num);
            tls_os_sem_release(hif->uart_atcmd_sem);
            break;
        case NET_EVENT_UDP_START_FAILED:
            tls_os_sem_release(hif->uart_atcmd_sem);
            break;
        default:
            break;
    }
}

static void  hostif_socket_state_changed_RICMD(u8 skt_num, u8 event, u8 state)
{
    struct tls_hostif *hif = tls_get_hostif();
	TLS_DBGPRT_INFO("event=%d, state=%d\n", event, state);
    switch (event) {
        case NET_EVENT_TCP_JOINED:
            tls_hostif_send_event_tcp_join(skt_num);
            break;
        case NET_EVENT_TCP_DISCONNECT:
            tls_hostif_send_event_tcp_dis(skt_num);
            break; 
        case NET_EVENT_TCP_CONNECTED:
            tls_hostif_send_event_tcp_conn(skt_num, 1);
            break;
        case NET_EVENT_TCP_CONNECT_FAILED:
            tls_hostif_send_event_tcp_conn(skt_num, 0);
            break;
        default:
            break;
    }
}

struct tls_socket_desc skt_desc;
/* 
 * @return: value 1-20 is socket num
 *          value 0 : socket is not availble
 *          value <0 is error
 * */
int tls_cmd_create_socket(struct tls_cmd_socket_t *skt,
        enum tls_cmd_mode cmd_mode)
{
    int ret;
    TLS_DBGPRT_INFO("=====>\n");
    TLS_DBGPRT_INFO("skt proto = %d\n", skt->proto);
    TLS_DBGPRT_INFO("skt client = %d\n", skt->client);
    TLS_DBGPRT_INFO("skt port = %d\n", skt->port);
    TLS_DBGPRT_INFO("skt ipaddr = 0x%x\n", get_unaligned_le32(skt->ip_addr));
    TLS_DBGPRT_INFO("cmd_mode = %d\n", cmd_mode);

    memset(&skt_desc, 0, sizeof(struct tls_socket_desc));
    skt_desc.cs_mode = skt->client ? SOCKET_CS_MODE_CLIENT : SOCKET_CS_MODE_SERVER;
    MEMCPY(skt_desc.host_name, skt->host_name, 32);
    skt_desc.host_len = skt->host_len;
    MEMCPY(skt_desc.ip_addr, skt->ip_addr, 4);
    skt_desc.localport = skt->localport;
    skt_desc.port = skt->port;
    skt_desc.protocol = (enum tls_socket_protocol)skt->proto;
    skt_desc.timeout = skt->timeout;
    skt_desc.recvf = hostif_socket_recv;
	skt_desc.recvwithipf = hostif_socket_rpt;
    if ((cmd_mode == CMD_MODE_UART0_ATCMD) ||
            (cmd_mode == CMD_MODE_UART1_ATCMD)) 
    {
        skt_desc.state_changed = hostif_socket_state_changed_ATCMD;
        TLS_DBGPRT_INFO("skt_desc.state_changed: 0x%x\n", skt_desc.state_changed);
    }
    else
    {
        skt_desc.state_changed = hostif_socket_state_changed_RICMD;
        TLS_DBGPRT_INFO("==>skt_desc.state_changed: 0x%x\n", skt_desc.state_changed);
    }
    ret = tls_socket_create(&skt_desc);
    if (ret <= 0)
        return -1;
    else 
        return ret;
}


int tls_cmd_close_socket(u8 skt_num)
{
    int err;

    err = tls_socket_close(skt_num);
    if(!err)
        free_recvmit(skt_num);

    return err;
}
        
int tls_cmd_get_socket_status(u8 socket, u8 *buf, u32 bufsize)
{
    int err;

    err = tls_socket_get_status(socket, buf, bufsize);
	
    return err;
}

int tls_cmd_get_socket_state(u8 socket, u8 * state, struct tls_skt_status_ext_t *skt_ext)
{
	struct tls_skt_status_t *skt_status = 0;
	struct tls_skt_status_ext_t *ext;
	int err;
	u32 buflen;
	buflen = sizeof(struct tls_skt_status_ext_t) * 5 +
                        sizeof(u32);
	skt_status = (struct tls_skt_status_t *)
                    tls_mem_alloc(buflen);
	if(skt_status == NULL)
		return NETCONN_STATE_NONE;
	memset(skt_status, 0, buflen);
	err = tls_cmd_get_socket_status(socket, (u8 *)skt_status, buflen);
	//TLS_DBGPRT_INFO("err=%d\n", err);
	if(err)
	{
		*state = NETCONN_STATE_NONE;
	}
	else
	{
		ext = &skt_status->skts_ext[0];
		if(skt_ext != NULL)
			MEMCPY(skt_ext, ext, sizeof(struct tls_skt_status_ext_t));
		*state = ext->status;
	}
	tls_mem_free(skt_status);
	//TLS_DBGPRT_INFO("state=%d\n", *state);
	return err;
}

u8 tls_cmd_get_default_socket(void)
{
    return default_socket;
}

int tls_cmd_set_default_socket(u8 socket)
{
    if (socket < 1 || socket > 20)
        return -1;

    default_socket = socket;
    return 0;
}

#endif //TLS_CONFIG_SOCKET_RAW

static void tls_hostif_wjoin_success(void)
{
    struct tls_hostif *hif = tls_get_hostif();
    if (hif->last_join) {
        hif->last_join = 0;
        if ((hif->last_join_cmd_mode == CMD_MODE_HSPI_RICMD) ||
                (hif->last_join_cmd_mode == CMD_MODE_UART1_RICMD)){          
            tls_hostif_send_event_wjoin_success(); 
	 }
        else if (hif->last_join_cmd_mode == CMD_MODE_UART1_ATCMD) {
            tls_os_sem_release(hif->uart_atcmd_sem); 
        } else if (hif->last_join_cmd_mode == CMD_MODE_UART0_ATCMD) {
            tls_os_sem_release(hif->uart_atcmd_sem); 
        } else
            ;
    } 
}

static void tls_hostif_wjoin_failed(void)
{ 
    struct tls_hostif *hif = tls_get_hostif();
    if (hif->last_join) {
        if ((hif->last_join_cmd_mode == CMD_MODE_HSPI_RICMD) ||
                (hif->last_join_cmd_mode == CMD_MODE_UART1_RICMD)){
            tls_hostif_send_event_wjoin_failed();
	 }
        else if (hif->last_join_cmd_mode == CMD_MODE_UART1_ATCMD) {
            tls_os_sem_release(hif->uart_atcmd_sem); 
        } else if (hif->last_join_cmd_mode == CMD_MODE_UART0_ATCMD) {
            tls_os_sem_release(hif->uart_atcmd_sem); 
        } else
            ;
        hif->last_join = 0;
    }
}

static void tls_hostif_net_status_changed(u8 status)
{
    switch(status)
    {
        case NETIF_WIFI_JOIN_FAILED:
            tls_hostif_wjoin_failed();
            break;
        case NETIF_WIFI_JOIN_SUCCESS:
#if TLS_CONFIG_APSTA
        case NETIF_WIFI_APSTA_AP_SUCCESS:
#endif
            tls_cmd_set_net_up(1);
            tls_hostif_wjoin_success();
            break;
        case NETIF_IP_NET_UP:

            tls_hostif_send_event_linkup(); 
#if TLS_CONFIG_SOCKET_RAW
            hostif_default_socket_create_tmr(1);
#endif //TLS_CONFIG_SOCKET_RAW
            break;
        case NETIF_WIFI_DISCONNECTED:
            tls_cmd_set_net_up(0);
            tls_hostif_send_event_linkdown(); 
#if TLS_CONFIG_SOCKET_RAW
            hostif_default_socket_stop_tmr();
#endif //TLS_CONFIG_SOCKET_RAW
            break;
        default:
            break;
    }
	
	return;
}

int tls_hostif_set_net_status_callback(void)
{
    return tls_netif_add_status_event(tls_hostif_net_status_changed);
}

#if TLS_CONFIG_HTTP_CLIENT_TASK
#define HTTP_TX_PKG_SIZE	512

void tls_hostif_http_client_recv_callback(HTTP_SESSION_HANDLE pSession, CHAR * data, u32 datalen)
{
	#undef CMDIND_BUF_SIZE
	#define CMDIND_BUF_SIZE 64
	char *cmdind_buf = NULL;
	int err1 = 0;
	u32 cmdind_size = 0;

	struct tls_hostif *hif = tls_get_hostif();

	if ((hif->rptmode) || (HOSTIF_MODE_HSPI == hif->hostif_mode))
	{		
		if(data == NULL && datalen > 0)
		{
			cmdind_buf = tls_mem_alloc(CMDIND_BUF_SIZE);
			if (cmdind_buf)
			{
				cmdind_size = sprintf(cmdind_buf,"+HTTPCRPT=%d,%d\r\n\r\n",pSession, datalen);
				err1 = tls_hostif_process_cmdrsp(hif->hostif_mode, cmdind_buf, cmdind_size);
				if (err1)
				{
					tls_mem_free(cmdind_buf);
					cmdind_buf = NULL;
					return;
				}
			}
		}
		else{
			if(data != NULL){
				err1 = tls_hostif_process_cmdrsp(hif->hostif_mode, data, datalen);
				if (err1)
				{
					tls_mem_free(data);
				}
			}
		}
	}
	else {
		if(data != NULL)
			tls_mem_free(data);
	}
}

void tls_hostif_http_client_err_callback(HTTP_SESSION_HANDLE pSession, int err)
{
	#undef CMDIND_BUF_SIZE
	#define CMDIND_BUF_SIZE 64
	char *cmdind_buf = NULL;
	int err1 = 0;
	u32 cmdind_size = 0;

	struct tls_hostif *hif = tls_get_hostif();

	if ((hif->rptmode) || (HOSTIF_MODE_HSPI == hif->hostif_mode))
	{		
		cmdind_buf = tls_mem_alloc(CMDIND_BUF_SIZE);
		if (cmdind_buf)
		{
			cmdind_size = sprintf(cmdind_buf,"+HTTPCERRRPT=%d,%d\r\n\r\n",pSession, err);
			err1 = tls_hostif_process_cmdrsp(hif->hostif_mode, cmdind_buf, cmdind_size);
			if (err1)
			{
				tls_mem_free(cmdind_buf);
				cmdind_buf = NULL;
			}
		}
	}
}

#endif

#endif /*TLS_CONFIG_HOSTIF*/
