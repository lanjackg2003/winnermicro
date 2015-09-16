/**************************************************************************
 * File Name                   : wm_cmdp_at.c
 * Author                       :
 * Version                      :
 * Date                          :
 * Description                 :
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd. 
 * All rights reserved.
 *
 ***************************************************************************/
#include "wm_config.h"
#include "wm_params.h"
#include "wm_cmdp_at.h"
#include "wm_debug.h"
#include "utils.h"
#include "wm_irq.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "wm_fwup.h"
#include "wm_efuse.h"
#include "litepoint.h"
#include "wm_irq.h"
#include "wm_uart_timer.h"
#include "wm_flash.h"
#include "wm_mem.h"
#include "wm_http_client.h"

/*Image File Create Date*/
const INT8U SysCreatedDate[] = __DATE__;
const INT8U SysCreatedTime[] = __TIME__;

#if TLS_CONFIG_HOSTIF 
#include "ucos_ii.h"
#include "wm_uart.h"
extern unsigned char hed_rf65_txgainmap[32];
extern u8* ieee80211_get_tx_gain(void);
extern u8 *wpa_supplicant_get_mac(void);
extern void wpa_supplicant_set_mac(u8 *mac);
#if TLS_CONFIG_APSTA
extern u8 *wpa_supplicant_get_mac2(void);
extern void wpa_supplicant_set_mac2(u8 *mac);
#endif
extern u32 hed_rf_read(u32 reg);
extern void hed_rf_write(u32 reg);
extern int hed_rf65_lo_leakage(signed short init_param, int do_calculate);
extern void tls_wifi_get_customdata(u8 *data);
#if TLS_CONFIG_SOCKET_RAW
#include "wm_sockets.h"
extern u32 tls_net_get_sourceip(void);
extern void tls_net_set_sourceip(u32 ipvalue);
#endif
extern void wm_cmdp_oneshot_status_event(u8 status);
extern	int wm_cmdp_oneshot_task_init(void);


#define AT_RESP_OK_STR_LEN    3
#define AT_RESP_ERR_STR_LEN   4

static const char at_resp_ok[] = "+OK";
static const char at_resp_err[] = "+ERR=";

int atcmd_filter_quotation(u8 **keyInfo, u8 *inbuf)
{
	if (*inbuf == '"'){/* argument such as  "xxxx" */
	
		inbuf++; /* skip 1st <"> */
		*keyInfo = inbuf;
	
		/* find end of string */
		while (*inbuf&& (*inbuf!= '"')) {
			++inbuf;
		}
		if (*inbuf == '\0'){
			return 1;
		}else{
			*inbuf++ = '\0';
		}
	}else{
		*keyInfo = inbuf;
	}

	return 0;
}

#if TLS_CONFIG_AT_CMD 

static int atcmd_insdisp_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
	struct tls_hostif *hif = tls_get_hostif();
    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        if (hif->uart_insdisp)
            hif->uart_insdisp = 0;
        else
            hif->uart_insdisp = 1;
        *res_len = atcmd_ok_resp(res_resp);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0; 
}

#if TLS_CONFIG_SOCKET_RAW
static int atcmd_entm_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u16 rx_fifocnt;
    u8 ch;
    int i;
#if TLS_CONFIG_UART
	cmd_set_uart1_mode_callback callback;
	struct tls_uart_port *uart1_port;
	cmd_get_uart1_port_callback port_callback;
	extern void tls_uart_rx_disable(struct tls_uart_port *port);
	extern void tls_uart_rx_enable(struct tls_uart_port *port);
#endif	

    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
#if TLS_CONFIG_UART	
        port_callback = tls_cmd_get_uart1_port();
        if(port_callback!=NULL)
            port_callback(&uart1_port);
        if (!uart1_port) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_NOT_ALLOW);
            return 0;
        }	
        callback = tls_cmd_get_set_uart1_mode();
        if(callback!=NULL)
            callback(UART_TRANS_MODE);

        tls_irq_disable(uart1_port->uart_irq_no);
        tls_uart_rx_disable(uart1_port);
        /* read all data from uart rx fifo */
        rx_fifocnt = (uart1_port->regs->UR_FIFOS >> 6) & 0x3F;
        for (i = 0; i < rx_fifocnt; i++)
            ch = (u8)uart1_port->regs->UR_RXW;
        
        (void)ch;

        /* reset uart rx ring buffer */
        uart1_port->recv.tail = uart1_port->recv.head; 

        tls_uart_rx_enable(uart1_port);
        tls_irq_enable(uart1_port->uart_irq_no); 
#endif
        *res_len = atcmd_ok_resp(res_resp);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0; 
}
#endif //TLS_CONFIG_SOCKET_RAW

static int atcmd_reset_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        tls_cmd_reset_sys();
        *res_len = atcmd_ok_resp(res_resp);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0; 
}

static int atcmd_ps_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_ps_t ps;
    int err = 0;
    int ret;
    u32 params;

    if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 4)) {
        do {
            ret = string_to_uint(tok->arg[0], &params);
            if (ret || params > 2) {
                err = 1;
                break;
            }
            ps.ps_type = (u8)params;

            ret = string_to_uint(tok->arg[1], &params);
            if (ret || params > 1) {
                err = 1;
                break;
            }
            ps.wake_type = (u8)params;

            if ((1 == ps.ps_type)||(2 == ps.ps_type)){
	            ret = string_to_uint(tok->arg[2], &params);
	            if (ret || params > 1000 || params < 10) {
	                err = 1;
	                break;
	            }
	            ps.delay_time = (u16)params;

	            ret = string_to_uint(tok->arg[3], &params);
	            if (ret || params > 65535 || params < 1000) {
	                err = 1;
	                break;
	            }
	            ps.wake_time = (u16)params; 
			}

            err = 0;
        } while (0);

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ret = tls_cmd_ps(&ps);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, ret);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    } 

    return 0;    
}

static int atcmd_reset_flash_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret;
    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        ret = tls_cmd_reset_flash();
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_FLASH);
        else 
            *res_len = atcmd_ok_resp(res_resp);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0; 
}

static int atcmd_pmtf_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret;

    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        ret = tls_cmd_pmtf();
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_FLASH);
        else 
            *res_len = atcmd_ok_resp(res_resp);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }

    return 0;
}

static int atcmd_gpio_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    if (tok->arg_found) {
        MEMCPY(res_resp, at_resp_err, AT_RESP_ERR_STR_LEN); 
        *res_len = AT_RESP_ERR_STR_LEN;
    } else {
        MEMCPY(res_resp, at_resp_ok, AT_RESP_OK_STR_LEN);
        *res_len = AT_RESP_OK_STR_LEN;
    }
    return 0;
}

static int atcmd_wjoin_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_connect_t *conn;
    int err; 
    int len, i;
	struct tls_hostif *hif = tls_get_hostif();
	struct tls_curr_bss_t *bss;

	conn = tls_mem_alloc(sizeof(struct tls_cmd_connect_t));
	if(!conn){
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_MEM);
		return 0;
	}

	bss = tls_mem_alloc(sizeof(struct tls_curr_bss_t));
	if(!bss){
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_MEM);
		tls_mem_free(conn);
		return 0;
	}
	
	memset(conn, 0, sizeof(struct tls_cmd_connect_t));
    memset(bss, 0, sizeof(struct tls_curr_bss_t));
	 
    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        conn->res = 0;
        err = tls_cmd_join(tok->cmd_mode, conn);
        if (conn->res == 1) {
            /* wlan is linkup, return link information */
            len = sprintf(res_resp, "+OK=%02x%02x%02x%02x%02x%02x,%d,%d,%d,\"",
                    conn->bssid[0],conn->bssid[1], conn->bssid[2],
                    conn->bssid[3],conn->bssid[4], conn->bssid[5],
                    conn->type, conn->channel,
                    (conn->encrypt?1:0));
            for (i = 0; i < conn->ssid_len; i++)
                sprintf(res_resp+len+i, "%c", conn->ssid[i]);
            *res_len = len + conn->ssid_len;
            len = sprintf(res_resp+len + conn->ssid_len, "\",%u", conn->rssi);
            *res_len += len; 
        } else if (err == CMD_ERR_OK) {
            /* waiting for 30 seconds: infact 20s, determind by wpa_supplicant_connect_timeout */
            err = tls_os_sem_acquire(hif->uart_atcmd_sem, 0);
            if (err) {
                *res_len =  atcmd_err_resp(res_resp, CMD_ERR_JOIN); 
            } else {
                if (tls_cmd_get_net_up()) {
					tls_wifi_get_current_bss(bss);
					#if 1
                    MEMCPY(conn->bssid, bss->bssid, ETH_ALEN);
                    conn->type = bss->type;
                    conn->encrypt = bss->encryptype;
                    conn->ssid_len = bss->ssid_len;
                    MEMCPY(conn->ssid, bss->ssid, bss->ssid_len);
                    conn->channel = bss->channel;
					conn->rssi = bss->rssi;
					#endif
                    len = sprintf(res_resp, "+OK=%02x%02x%02x%02x%02x%02x,%d,%d,%d,\"",
                            conn->bssid[0],conn->bssid[1], conn->bssid[2],
                            conn->bssid[3],conn->bssid[4], conn->bssid[5],
                            conn->type, conn->channel,
                            (conn->encrypt?1:0));
                    for (i = 0; i < conn->ssid_len; i++)
                        sprintf(res_resp+len+i, "%c", conn->ssid[i]);
                    *res_len = len + conn->ssid_len;
                    len = sprintf(res_resp+len + conn->ssid_len, "\",%u", conn->rssi);
                    *res_len += len; 
                } else {
                    *res_len =  atcmd_err_resp(res_resp, CMD_ERR_JOIN); 
                }
            }
        } else {
            *res_len = atcmd_err_resp(res_resp, err);
        }
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
	tls_mem_free(conn);
	tls_mem_free(bss);
    return 0;
}

static int atcmd_wleave_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
	int ret = WM_SUCCESS;
    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        ret = tls_cmd_disconnect_network();
		if(ret == WM_SUCCESS)
	        *res_len = atcmd_ok_resp(res_resp);
		else
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_FLASH);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }

    return 0;
}

static int atcmd_wscan_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret;
	struct tls_hostif *hif = tls_get_hostif();
    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        ret = tls_cmd_scan(tok->cmd_mode);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, ret);
        else {
            /* waiting for 30 seconds */
            ret = tls_os_sem_acquire(hif->uart_atcmd_sem, 5*HZ);
            if (ret) {
                *res_len =  atcmd_err_resp(res_resp, CMD_ERR_OPS); 
            } else {
                *res_len = 0; 
            } 
        }
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0;
}

static int atcmd_link_status_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_link_status_t lk;

    if (!tok->arg_found && ((tok->op == ATCMD_OP_NULL)||(tok->op == ATCMD_OP_QU))) {
        tls_cmd_get_link_status(&lk);
        if (lk.status == 0) {
            *res_len = sprintf(res_resp, "+OK=%u", lk.status);
        } else {
            *res_len = sprintf(res_resp, "+OK=%d,\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\"",
                lk.status,
                lk.ip[0], lk.ip[1], lk.ip[2], lk.ip[3],
                lk.netmask[0], lk.netmask[1], lk.netmask[2], lk.netmask[3],
                lk.gw[0], lk.gw[1], lk.gw[2], lk.gw[3],
                lk.dns1[0], lk.dns1[1], lk.dns1[2], lk.dns1[3],
                lk.dns2[0], lk.dns2[1], lk.dns2[2], lk.dns2[3]);
        }
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0;
}

#if TLS_CONFIG_AP
static int atcmd_get_sta_info( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
#define STA_DETAIL_BUF_LEN  512
    u8 mode;
    u32 sta_num = 0;
    u8 *sta_detail; 

    if (!tok->arg_found && ((tok->op == ATCMD_OP_NULL)||(tok->op == ATCMD_OP_QU)))
    {
        tls_cmd_get_wireless_mode(&mode);
        if ((IEEE80211_MODE_AP == mode)
#if TLS_CONFIG_APSTA
            || (IEEE80211_MODE_APSTA == mode)
#endif
           )
        {
            sta_detail = tls_mem_alloc(STA_DETAIL_BUF_LEN);
            if (NULL == sta_detail)
            {
                *res_len = atcmd_err_resp(res_resp, CMD_ERR_MEM);
                return 0;
            }
            memset(sta_detail, 0, STA_DETAIL_BUF_LEN);
            tls_cmd_get_sta_detail(&sta_num, sta_detail);
            *res_len = sprintf(res_resp, "+OK=%u%s", sta_num, sta_detail);
            tls_mem_free(sta_detail);
        }
        else
        {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        }
    }
    else
    {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0;
}
#endif

#if TLS_CONFIG_SOCKET_RAW
static int atcmd_skct_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_socket_t socket;
    u32    params;
    int err = 0;
    int ret;
    int socket_num;
    int host_len;
    u8 state;
    u8 *ipstr = NULL;
	struct hostent* HostEntry;
	struct tls_hostif *hif = tls_get_hostif();

    if(tok->op != ATCMD_OP_EQ)
    {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    }

    if((tok->arg_found != 4) && (tok->arg_found != 5))
    {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    }

    do {
        memset(&socket, 0, sizeof(struct tls_cmd_socket_t));
        /* check protol argument */
        ret = string_to_uint(tok->arg[0], &params);
        if (ret || params > 1) {
            err = 1;
            break;
        }
        socket.proto = (u8)params;
        /* check clinet/sever argument */
        ret = string_to_uint(tok->arg[1], &params);
        if (ret || params > 1) {
            err = 1;
            break;
        }
        socket.client = (u8)params ? 0 : 1;
        host_len = tok->arg[3] - tok->arg[2] - 1;
        if (host_len > 32) {
            err = 1;
            break;
        }
        /* check ip or timeout  */
        if (socket.client) {
			ret = string_to_ipaddr(tok->arg[2], (u8 *)&params);
			if (!ret){
				MEMCPY(socket.ip_addr, (u8 *)&params, 4); 
			}else
			{					
				atcmd_filter_quotation(&ipstr, (u8 *)tok->arg[2]);	
				HostEntry = gethostbyname((char *)ipstr); 
				if(HostEntry)
				{
					MEMCPY(socket.ip_addr, HostEntry->h_addr_list[0], 4);
                } else {
                    err = 1;
                    break;
                }
			}
            MEMCPY(socket.host_name, tok->arg[2], host_len);
        } else {
            if (socket.proto == 0) {
				if (*tok->arg[2] != '\0'){
                    ret = string_to_uint(tok->arg[2], &params);
                    if (ret || params > 10000000) {
                        err = 1;
                        break;
                    }
                    socket.timeout = params; 
				}
            }
        }
        /* check port */
        ret = string_to_uint(tok->arg[3], &params);
        if (ret || (params > 0xFFFF)) {
            err = 1;
            break;
        }
        if((tok->arg_found == 4) && (params == 0))
        {
            err = 1;
            break;
        }
        socket.port = params; 
        socket.host_len = host_len;
    /* check local port */
        if(tok->arg_found == 5)
        {
            ret = string_to_uint(tok->arg[4], &params);
            if (ret || (params > 0xFFFF)) {
                err = 1;
                break;
            }
            if((socket.proto == 0) && (socket.client == 0))
            {
                if(params != 0)
                {
                    socket.port = params;
                }
                else
                {
                    if(socket.port == 0)
                    {
                        err = 1;
                        break;
                    }
                }
            }
            else
            {
                if((params == 0) || (socket.port == 0))
                {
                    err = 1;
                    break;
                }
            }
            socket.localport = params;
        }
 
//        if((socket.proto == 1) && (socket.client == 1) && (tok->arg_found == 4))
//        {
//            socket.localport = socket.port;
//        }

        err = 0;
    } while (0);

    if (!err) {
        socket_num = tls_cmd_create_socket(&socket, tok->cmd_mode);
        if (socket_num > 0 && socket_num <= TLS_MAX_NETCONN_NUM) {
            /* waiting for 25 seconds */
            err = tls_os_sem_acquire(hif->uart_atcmd_sem, 25*HZ);
            if (err) {
                *res_len =  atcmd_err_resp(res_resp, CMD_ERR_SKT_CONN); 
            } else {
                tls_cmd_get_socket_state(socket_num, &state, NULL);
                if (state != NETCONN_STATE_NONE)
                    *res_len = sprintf(res_resp, "+OK=%d", socket_num);
                else
                    *res_len = atcmd_err_resp(res_resp, CMD_ERR_SKT_CONN); 
            }
        } else if (socket_num == 0) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_NO_SKT);
        } else
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_SKT_CONN); 
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
    }
    
    return 0;
}

static int atcmd_skstt_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_skt_status_t *skt_status = 0;
    struct tls_skt_status_ext_t *ext;
    int err;
    u8 socket;
    u32 params;
    u32 buflen;
    int i;
    struct tls_uart_circ_buf * precvmit = NULL;
    if ((tok->arg_found == 1) && (tok->op == ATCMD_OP_EQ)) {
        err = string_to_uint(tok->arg[0], &params);
        if (!err) {
            if (params <= 20) {
                socket = params;
                buflen = sizeof(struct tls_skt_status_ext_t) * 5 +
                        sizeof(u32);
                skt_status = (struct tls_skt_status_t *)
                    tls_mem_alloc(buflen);
                if (!skt_status) {
                    *res_len = atcmd_err_resp(res_resp, CMD_ERR_MEM);
                    return 0;
                } else  {
                    memset(skt_status, 0, buflen);
                    err = tls_cmd_get_socket_status(socket,
                            (u8 *)skt_status, buflen);
                }
            } else
                err = 1;
        }
        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        } else {
            *res_len = sprintf(res_resp, "+OK=");
            ext = &skt_status->skts_ext[0];
            
            for (i = 0; i < skt_status->socket_cnt; i++) {
                precvmit =tls_hostif_get_recvmit(ext->socket);
                if(precvmit == NULL)
                    buflen = 0;
                else
                    buflen = CIRC_CNT(precvmit->head, precvmit->tail, TLS_SOCKET_RECV_BUF_SIZE);
                *res_len += sprintf(res_resp + (*res_len), 
                        "%d,%d,\"%d.%d.%d.%d\",%d,%d,%d\r\n",
                    ext->socket, ext->status, 
                    ext->host_ipaddr[0], ext->host_ipaddr[1], 
                    ext->host_ipaddr[2], ext->host_ipaddr[3],
                    ext->remote_port,ext->local_port, buflen); 
                ext++;
            } 
        }
        if (skt_status)
            tls_mem_free(skt_status);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
    }
    return 0;
}

static int atcmd_skclose_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int err;
    u32 params;

    if (tok->arg_found == 1 && (tok->op == ATCMD_OP_EQ)) {
        err = string_to_uint(tok->arg[0], &params);
        if (!err && (params > 0 && params <= TLS_MAX_NETCONN_NUM)) {
            err = tls_cmd_close_socket((u8)params);
		if(err)
            		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		else
			*res_len = sprintf(res_resp, "+OK");
        } else {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        }
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS); 
    }
    return 0;
}

static int atcmd_sksdf_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int err;
    u32 params;

    if ((tok->arg_found == 1) && (tok->op == ATCMD_OP_EQ)) {
        err = string_to_uint(tok->arg[0], &params);
        if (!err && ((params >= 1) && (params <= 20))) {
            err = tls_cmd_set_default_socket((u8)params);
        } else {
            err = 1;
        }

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0;
}

static int atcmd_sksnd_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int err = 0;
    int ret;
    u32 params;
    u32 socket = 0, size = 0;
	cmd_set_uart1_mode_callback callback;
	cmd_set_uart1_sock_param_callback sock_callback;
	struct tls_hostif *hif = tls_get_hostif();
    u8 state;
    if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 2)) {
        do {
            ret = string_to_uint(tok->arg[0], &params);
            if (ret || params > 20 || params < 1) {
                err = 1;
                break;
            }
            socket = (int)params;

            ret = string_to_uint(tok->arg[1], &params);
            if (ret) {
                err = 1;
                break;
            }
            size = (int)params;
            if (size > 1024)
                size = 1024;


        } while (0);
        tls_cmd_get_socket_state(socket, &state, NULL);
        if (err || state != NETCONN_STATE_CONNECTED) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        } else {
            *res_len = sprintf(res_resp, "+OK=%u", size); 
			tls_cmd_set_default_socket(socket);
			if (hif->hostif_mode == HOSTIF_MODE_UART1_LS){
				TLS_DBGPRT_INFO("start timer2\n");
				sock_callback = tls_cmd_get_set_uart1_sock_param();
				if(sock_callback!=NULL)
					sock_callback(size, false);
				tls_timer2_start(500);
				callback = tls_cmd_get_set_uart1_mode();
				if(callback!=NULL)
					callback(UART_ATSND_MODE);
			}
        } 
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    return 0;    
}

static int atcmd_skrcv_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    /*if (tok->arg_found) {
        MEMCPY(res_resp, at_resp_err, AT_RESP_ERR_STR_LEN); 
        *res_len = AT_RESP_ERR_STR_LEN;
    } else {
        MEMCPY(res_resp, at_resp_ok, AT_RESP_OK_STR_LEN);
        *res_len = AT_RESP_OK_STR_LEN;
    }*/

    int err = 0;
    int ret;
    u32 params;
    u32 socket = 0, size = 0;
    u8 state;
    if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 2)) {
        do {
            ret = string_to_uint(tok->arg[0], &params);
            if (ret || params > 20 || params < 1) {
                err = 1;
                break;
            }
            socket = (int)params;

            ret = string_to_uint(tok->arg[1], &params);
            if (ret) {
                err = 1;
                break;
            }
            size = (int)params;
            if (size > 1024)
                size = 1024;


        } while (0);
        tls_cmd_get_socket_state(socket, &state, NULL);
        if (err || state != NETCONN_STATE_CONNECTED) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        } else {
            *res_len = sprintf(res_resp, "%d,%d", socket, size); 

        } 
    } 
    else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    return 0;
}

static int atcmd_sktrptmode_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret, mode;
	struct tls_hostif *hif = tls_get_hostif();

	if (ATCMD_OP_QU == tok->op)
	{
		*res_len = sprintf(res_resp, "+OK=%d\n", hif->rptmode);
	}else{
	    if((1 != tok->arg_found) || (ATCMD_OP_EQ != tok->op))
	   	{
	   		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
	    }
		ret = string_to_uint(tok->arg[0], (u32 *)&mode);
		if(ret) 
		{
			TLS_DBGPRT_ERR("autoreport param err! %x\r\n", ret);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}

		if (1 == mode)
		{
			hif->rptmode = mode;
		}else
		{
			hif->rptmode = mode;
		}

		*res_len = atcmd_ok_resp(res_resp); 
	}

	return 0;

}

static int atcmd_sktsrceip_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u32 ipvalue;
	if (ATCMD_OP_QU == tok->op)
	{
		ipvalue = tls_net_get_sourceip();
		*res_len = sprintf(res_resp, "+OK=%d.%d.%d.%d", ipvalue&0xFF, (ipvalue>>8)&0xFF, (ipvalue>>16)&0xFF,(ipvalue>>24)&0xFF);
		tls_net_set_sourceip(0);
	}else{
		*res_len = atcmd_err_resp(res_resp,CMD_ERR_UNSUPP);
	}
	return 0;
}

static int atcmd_skghbn_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u8 *ipstr = NULL;
	struct hostent* HostEntry;
	
	if (tok->op == ATCMD_OP_EQ)
	{
		if (tok->arg_found == 1)
		{
			atcmd_filter_quotation(&ipstr, (u8 *)tok->arg[0]);	
			HostEntry = gethostbyname((char *)ipstr); 
			if(HostEntry)
			{
				*res_len = sprintf(res_resp, "+OK=%d.%d.%d.%d", \
					*HostEntry->h_addr_list[0], *(HostEntry->h_addr_list[0] + 1), \
					*(HostEntry->h_addr_list[0] + 2), *(HostEntry->h_addr_list[0] + 3));
			} 
			else 
			{
				*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			}
		}
		else
		{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		}
	}
	else
	{
		*res_len = atcmd_err_resp(res_resp,CMD_ERR_UNSUPP);
	}
	return 0;
}

#endif //TLS_CONFIG_SOCKET_RAW

static int atcmd_wprt_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u8 mode;
    int ret = 0; 
    u32 param;
    u8 update_flash = 0;
    u8 set_opt = 0;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret || param > 3) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        } 
        mode = (u8)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_wireless_mode(mode, update_flash); 
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_wireless_mode(&mode); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else
            *res_len = sprintf(res_resp, "+OK=%u", mode);
    }
    return 0;
}

static int atcmd_ssid_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    struct tls_cmd_ssid_t ssid;
    int i;
	u8 *tmpssid;

    if (tok->arg_found == 1) {
		ret = atcmd_filter_quotation(&tmpssid, (u8 *)tok->arg[0]);
		if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
		}
		TLS_DBGPRT_INFO("tmpssid:%s\n",tmpssid);
        ssid.ssid_len = strlen((char *)tmpssid);
        if (ssid.ssid_len > 32 || ssid.ssid_len < 1) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        } 
        MEMCPY(ssid.ssid, tmpssid, ssid.ssid_len);
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_ssid(&ssid, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_ssid(&ssid);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=");
            for (i = 0; i<ssid.ssid_len; i++)
                *res_len += sprintf(res_resp + (*res_len), "%c", ssid.ssid[i]);
        }
    }
    return 0;
}

static int atcmd_key_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_key_t key;
    u8 update_flash = 0;
    u8 set_opt = 0;
    int err = 0;
    int ret;
    u32 params;
    int len;
    u8 *keyInfo;
	TLS_DBGPRT_INFO("tok->op:%d,%d\n", tok->op,tok->arg_found);

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 3)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 3)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    }

    if (set_opt) {
        do {
            err = strtodec((int *)&params, tok->arg[0]);
            if (err || params > 1) {
                err = 1;
                break;
            }
            key.format = (u8)params;

            err = strtodec((int *)&params, tok->arg[1]);
            if (err || params > 4) {
                err = 2;
                break;
            }
            key.index = (u8)params;

			err = atcmd_filter_quotation(&keyInfo,(u8 *)tok->arg[2]);

            key.key_len = strlen((char *)keyInfo);
            if (key.key_len > 64) {
                err = 3;
                break;
            }
            MEMCPY(key.key, keyInfo, key.key_len); 
        } while (0);

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ret = tls_cmd_set_key(&key, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_key(&key); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            len = sprintf(res_resp, "+OK=%u,%u,", key.format, key.index);
            MEMCPY(res_resp + len, key.key, key.key_len);
            *res_len = len + key.key_len;
        }
    }
    return 0;    
}

#if TLS_CONFIG_APSTA
static int atcmd_ssid2_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    struct tls_cmd_ssid_t ssid;
    int i;
	u8 *tmpssid;

    if (tok->arg_found == 1) {
		ret = atcmd_filter_quotation(&tmpssid, (u8 *)tok->arg[0]);
		if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
		}
		TLS_DBGPRT_INFO("tmpssid:%s\n",tmpssid);
        ssid.ssid_len = strlen((char *)tmpssid);
        if (ssid.ssid_len > 32) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        } 
        MEMCPY(ssid.ssid, tmpssid, ssid.ssid_len);
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_ssid2(&ssid, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_ssid2(&ssid);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=");
            for (i = 0; i<ssid.ssid_len; i++)
                *res_len += sprintf(res_resp + (*res_len), "%c", ssid.ssid[i]);
        }
    }
    return 0;
}

static int atcmd_mac2_proc(
	struct tls_atcmd_token_t *tok, 
	char *res_resp, u32 *res_len)
{
	u8 *mac = NULL;
	u8 *tmpmac = NULL;

	if (!tok->arg_found && 
		((tok->op == ATCMD_OP_NULL) || (tok->op == ATCMD_OP_QU))) 
	{
		mac = wpa_supplicant_get_mac2();
		*res_len = sprintf(res_resp, "+OK=%02x%02x%02x%02x%02x%02x", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); 
	} 
	else if (tok->arg_found &&((tok->op == ATCMD_OP_EP)||(tok->op== ATCMD_OP_EQ)))
	{
		if (atcmd_filter_quotation(&tmpmac, (u8 *)tok->arg[0])){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		}

		mac = tls_mem_alloc(ETH_ALEN);		
		if (mac){
			if (strtohexarray(mac, ETH_ALEN, (char *)tmpmac)< 0){
				*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
			}else{
				wpa_supplicant_set_mac2(mac);
				*res_len = atcmd_ok_resp(res_resp);
			}
			tls_mem_free(mac);
			mac = NULL;
		}else{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		}
	}
	else
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}
	return 0;
}

static int atcmd_link2_status_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_link_status_t lk;

    if (!tok->arg_found && ((tok->op == ATCMD_OP_NULL)||(tok->op == ATCMD_OP_QU))) {
        tls_cmd_get_link2_status(&lk);
        if (lk.status == 0) {
            *res_len = sprintf(res_resp, "+OK=%u", lk.status);
        } else {
            *res_len = sprintf(res_resp, "+OK=%d,\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\",\"%d.%d.%d.%d\"",
                lk.status,
                lk.ip[0], lk.ip[1], lk.ip[2], lk.ip[3],
                lk.netmask[0], lk.netmask[1], lk.netmask[2], lk.netmask[3],
                lk.gw[0], lk.gw[1], lk.gw[2], lk.gw[3],
                lk.dns1[0], lk.dns1[1], lk.dns1[2], lk.dns1[3],
                lk.dns2[0], lk.dns2[1], lk.dns2[2], lk.dns2[3]);
        }
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
    return 0;
}
#endif

static int atcmd_encrypt_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    u32 params;
    u8 encrypt;
    int err;

    if (tok->arg_found == 1) {
        err = string_to_uint(tok->arg[0], &params);
        if (err || params > 8) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        }
        encrypt = (u8)params;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_encrypt(encrypt, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_encrypt(&encrypt); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=%u", encrypt);
        }
    }
    return 0;
}

static int atcmd_bssid_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_bssid_t bssid;
    u8 update_flash = 0;
    u8 set_opt = 0;
    int err = 0;
    int ret;
    u32 params;
    int len;
    int i, j;
    int h, l;

    if ((tok->op == ATCMD_OP_EP) && ((tok->arg_found == 1) || (tok->arg_found == 2))) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1) || (tok->arg_found == 2)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0; 
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        do {
            ret = string_to_uint(tok->arg[0], &params);
            if (ret || params > 1) {
                err = 1;
                break;
            }
            bssid.enable = (u8)params;
            if((bssid.enable==0) && (tok->arg_found==2))
            {
                err = 1;
                break;
            }
            if((bssid.enable==1) && (tok->arg_found==1))
            {
                err = 1;
                break;
            }
            if(bssid.enable==1)
            {
                len = tok->arg[2] - tok->arg[1] - 1;
                if (len == 12) {
                    for (i = 0, j=0; i<len; i+= 2, j++) {
                        h = hex_to_digit(tok->arg[1][i]);
                        l = hex_to_digit(tok->arg[1][i+1]);
                        if (h < 0 || l < 0) {
                            err = 1;
                            break;
                        }
                        bssid.bssid[j] = h<<4 | l; 
                    } 
    			}else {
                    err = 1;
                    break;
                }
            }
        } while (0);

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ret = tls_cmd_set_bssid(&bssid, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_bssid(&bssid); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            if(bssid.enable)
            {
                *res_len = sprintf(res_resp, "+OK=%u,%02x%02x%02x%02x%02x%02x", 
                        bssid.enable,
                        bssid.bssid[0],bssid.bssid[1],bssid.bssid[2],
                        bssid.bssid[3],bssid.bssid[4],bssid.bssid[5]);
            }
            else
            {
                *res_len = sprintf(res_resp, "+OK=%u",bssid.enable);
            }
        }
    }
    return 0;    
}

static int atcmd_brd_ssid_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    u32 param;
    u8 ssid_set;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret || param > 1) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ssid_set = (u8)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_hide_ssid(ssid_set, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_hide_ssid(&ssid_set); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=%u", ssid_set);
        }
    }
    return 0;
}

static int atcmd_get_connect_param_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
	struct tls_cmd_bssid_t bssid;
	int ret = 0,i = 0; 
	struct tls_param_ssid original_ssid;
	struct tls_param_original_key original_key;

    memset(&bssid, 0, sizeof(struct tls_cmd_bssid_t));
    memset(&original_ssid, 0, sizeof(struct tls_param_ssid));
	memset(&original_key, 0, sizeof(struct tls_param_original_key));

    if(((tok->op==ATCMD_OP_NULL) || (tok->op==ATCMD_OP_QU)) && (tok->arg_found==0))
    {
        ret = tls_cmd_get_bssid(&bssid); 
    	if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else 
    	{
    		if(bssid.enable)
    		{
    		    ret = tls_cmd_get_original_key(&original_key);
                if(ret!=0)
                {
                     *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
                     return 0;
    		    }
    				  
    		   *res_len = sprintf(res_resp, "+OK=%u,%02x%02x%02x%02x%02x%02x,", 
                      bssid.enable,
                      bssid.bssid[0],bssid.bssid[1],bssid.bssid[2],
                      bssid.bssid[3],bssid.bssid[4],bssid.bssid[5]);
                MEMCPY(res_resp + *res_len, original_key.psk, original_key.key_length);
                *res_len += original_key.key_length;
    		}
    		else
    		{
                tls_cmd_get_original_ssid(&original_ssid);
    		    ret = tls_cmd_get_original_key(&original_key);
    	        if(ret!=0)
                {
                    *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
                    return 0;
    		    }
    			
                *res_len = sprintf(res_resp, "+OK=%u,", bssid.enable);
                for (i = 0; i<original_ssid.ssid_len; i++)
                    *res_len += sprintf(res_resp + (*res_len), "%c", original_ssid.ssid[i]);
    		    *res_len += sprintf(res_resp + *res_len,",");
                MEMCPY(res_resp + *res_len, original_key.psk, original_key.key_length);
                *res_len += original_key.key_length;
    		}
    	}
    }
    else
    {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }
	return 0;
}

static int atcmd_chnl_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u8 channel;
    u8 channel_en;
    u8 update_flash = 0;
    u8 set_opt = 0;
    int err = 0;
    int ret;
    u32 params;

    if ((tok->op == ATCMD_OP_EP) && ((tok->arg_found == 1)||(tok->arg_found == 2))) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && ((tok->arg_found == 1)||(tok->arg_found == 2))){
        set_opt = 1;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    }else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        do {
            ret = string_to_uint(tok->arg[0], &params);
            if (ret || params > 1) {
                err = 1;
                break;
            }
            channel_en = (u8)params;
			if((channel_en == 0) && (tok->arg_found > 1))
			{
                err = 1;
                break;
            }
			if(channel_en == 0){//config to auto mode
				channel = 1;
				err = 0;
				break;
			}
            ret = string_to_uint(tok->arg[1], &params);
            if (ret || params > 14 || params < 1) {
                err = 1;
                break;
            }
            channel = (u8)params;
            err = 0;
        } while (0);

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ret = tls_cmd_set_channel(channel, channel_en, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_channel(&channel, &channel_en); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            if(channel_en)
            {
                *res_len = sprintf(res_resp, "+OK=%u,%u", channel_en, channel);
            }
            else
            {
                *res_len = sprintf(res_resp, "+OK=%u", channel_en);
            }
        }
    }
    return 0;    
}

static int atcmd_chll_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
	u16 channellist;
	u8 update_flash = 0;
	u8 set_opt = 0;
	int ret;
	u32 param;

    if (tok->arg_found == 1) {
        ret = strtohex(&param, tok->arg[0]);
        if (ret || ((param & (~0x3fff))||(param == 0))) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        channellist = (u16)param;
    }

	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		set_opt = 1;
		update_flash = 1; 
	} else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		set_opt = 1;
		update_flash = 0;
	} else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		set_opt = 0;
	} else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		set_opt = 0;
	} else {
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	} 

	if (set_opt) {
		ret = tls_cmd_set_channellist(channellist, update_flash);
		if (ret) {
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		} else {
			*res_len = atcmd_ok_resp(res_resp);
		}
	} else {
		ret = tls_cmd_get_channellist(&channellist); 
		if (ret)
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		else {
			*res_len = sprintf(res_resp, "+OK=%04x", channellist);
		}
	}
	return 0;	 
}


static int atcmd_wreg_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    u32 param;
    u16 region;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        region = (u16)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_region(region, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_region(&region); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=%u", region);
        }
    }
    return 0;
}

static int atcmd_wbgr_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_wl_hw_mode_t hw_mode;
    u8 update_flash = 0;
    u8 set_opt = 0;
    int err = 0;
    int ret;
    u32 params;
	int limit_rate;

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 2)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 2)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        do {
            ret = string_to_uint(tok->arg[0], &params);
            if (ret ) { //|| params > 1
                err = 1;
                break;
            }
            hw_mode.hw_mode = (u8)params;
            ret = string_to_uint(tok->arg[1], &params);
            if (ret) {
                err = 1;
                break;
            }
			limit_rate = (hw_mode.hw_mode == 1)?3:((hw_mode.hw_mode == 2)? 28:11);
            hw_mode.max_rate = (params > limit_rate)?limit_rate: params; 
            err = 0;
        } while (0);

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ret = tls_cmd_set_hw_mode(&hw_mode, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_hw_mode(&hw_mode);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=%u,%u", hw_mode.hw_mode,
                    hw_mode.max_rate);
        }
    }
    return 0;    
}

static int atcmd_watc_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u8 mode;
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    u32 param;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret || param > 1) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        mode = (u8)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_adhoc_create_mode(mode, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_adhoc_create_mode(&mode); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=%u", mode);
        }
    }
    return 0;
}

static int atcmd_wpsm_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u8 mode;
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    u32 param;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret || param > 1) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        mode = (u8)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_wl_ps_mode(mode, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_wl_ps_mode(&mode);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=%u", mode);
        }
    }
    return 0;
}

static int atcmd_warm_proc(
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u8 mode;
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
    u32 param;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret || param > 1) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        mode = (u8)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_roaming_mode(mode, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_roaming_mode(&mode);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, "+OK=%u", mode);
        }
    }
    return 0;
}

static int atcmd_warc_proc(
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
	u8 autoretrycnt;
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;
	u32 param;

    if (tok->arg_found == 1) {
		ret = strtodec((int *)&param, (char *)tok->arg[0]);
		if (ret || param > 255) {
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		autoretrycnt = (u8)param;
    }

	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		set_opt = 1;
		update_flash = 1; 
	} else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		set_opt = 1;
		update_flash = 0;
	} else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		set_opt = 0;
	} else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		set_opt = 0;
	} else {
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	} 

	if (set_opt) {
		ret = tls_cmd_set_warc(autoretrycnt, update_flash);
		if (ret) {
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		} else {
			*res_len = atcmd_ok_resp(res_resp);
		}
	} else {
		ret = tls_cmd_get_warc(&autoretrycnt);
		if (ret)
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		else {
			*res_len = sprintf(res_resp, "+OK=%d", autoretrycnt);
		}
	}
	return 0;
}

static int atcmd_nip_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_ip_params_t ip_info;
    u8 update_flash = 0;
    u8 set_opt = 0;
    int err = 0;
    int ret;
    u32 params;
	u8 *tmpbuf;

    if ((tok->op == ATCMD_OP_EP)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        do {
            if (tok->arg_found == 1 || tok->arg_found == 5) {
                /* type : 0 or 1 */
                ret = string_to_uint(tok->arg[0], &params);
                if (ret || params > 1) {
                    err = 1;
                    break;
                }
                ip_info.type = (u8)params; 
                if ((tok->arg_found == 1 && ip_info.type != 0) ||
                        (tok->arg_found == 5 && ip_info.type !=1)) {
                    err = 1;
                    break;
                } 
                if (tok->arg_found == 1)
                    break;
            } else {
                err = 1; 
                break;
            }

            /* ip */
			ret = atcmd_filter_quotation(&tmpbuf,(u8 *)tok->arg[1]);
			if (ret){
				err = 1;
				break;
			}
            ret = string_to_ipaddr((char *)tmpbuf, (u8 *)&params);
            if (ret) {
                err = 1;
                break;
            }
            MEMCPY(ip_info.ip_addr, (u8 *)&params, 4);
            /* netmask */
			ret = atcmd_filter_quotation(&tmpbuf,(u8 *)tok->arg[2]);
			if (ret){
				err = 1;
				break;
			}			
            ret = string_to_ipaddr((char *)tmpbuf, (u8 *)&params);
            if (ret) {
                err = 1;
                break;
            }
            MEMCPY(ip_info.netmask, (u8 *)&params, 4);
            /* gateway */
			ret = atcmd_filter_quotation(&tmpbuf,(u8 *)tok->arg[3]);
			if (ret){
				err = 1;
				break;
			}			
            ret = string_to_ipaddr((char *)tmpbuf, (u8 *)&params);
            if (ret) {
                err = 1;
                break;
            }
            MEMCPY(ip_info.gateway, (u8 *)&params, 4);
            /* dns */
			ret = atcmd_filter_quotation(&tmpbuf,(u8 *)tok->arg[4]);
			if (ret){
				err = 1;
				break;
			}			
            ret = string_to_ipaddr((char *)tmpbuf, (u8 *)&params);
            if (ret) {
                err = 1;
                break;
            }
            MEMCPY(ip_info.dns, (u8 *)&params, 4);

            err = 0;
        } while (0);

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ret = tls_cmd_set_ip_info(&ip_info, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_ip_info(&ip_info);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
#if 0			
            if (ip_info.type == 0) {
                *res_len = sprintf(res_resp, "+OK=%u", ip_info.type);
            } else 
#endif
            {
                *res_len = sprintf(res_resp, 
                    "+OK=%u,%u.%u.%u.%u,%u.%u.%u.%u,%u.%u.%u.%u,%u.%u.%u.%u",
                    ip_info.type,
                    ip_info.ip_addr[0], ip_info.ip_addr[1],
                    ip_info.ip_addr[2], ip_info.ip_addr[3],
                    ip_info.netmask[0], ip_info.netmask[1],
                    ip_info.netmask[2], ip_info.netmask[3],
                    ip_info.gateway[0], ip_info.gateway[1],
                    ip_info.gateway[2], ip_info.gateway[3],
                    ip_info.dns[0], ip_info.dns[1],
                    ip_info.dns[2], ip_info.dns[3]);
            }
        }
    }
    return 0;    
}

static int atcmd_atm_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u8 mode;
    int ret = 0; 
    u32 param;
    u8 update_flash = 0;
    u8 set_opt = 0;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret || param > 1) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        } 
        mode = (u8)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_work_mode(mode, update_flash); 
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_work_mode(&mode); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else
            *res_len = sprintf(res_resp, "+OK=%u", mode);
    }
    return 0;
}

static int atcmd_atrm_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_socket_t socket;
    u32  params;
    int err = 0;
    int ret;
    u8 set_opt = 0;
    u8 update_flash = 0;
    u8 *tmp;

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 4)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 4)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        return 0;
    } 

    if (set_opt) {
        do {
            memset(&socket, 0, sizeof(struct tls_cmd_socket_t));
            /* check protol argument */
            ret = string_to_uint(tok->arg[0], &params);
            if (ret || params > 1) {
                err = 1;
                break;
            }
            socket.proto = (u8)params;
            /* check clinet/sever argument */
            ret = string_to_uint(tok->arg[1], &params);
            if (ret || params > 1) {
                err = 1;
                break;
            }
            socket.client = (u8)params ? 0 : 1;
			ret = atcmd_filter_quotation(&tmp, (u8 *)tok->arg[2]);
			if (ret){
				err = 1;
				break;
			}

            socket.host_len = strlen((char *)tmp);
            if (socket.host_len > 32) {
                err = 1;
                break;
            }
            /* check ip or timeout  */
            if (socket.client) {
                ret = string_to_ipaddr((char *)tmp, (u8 *)&params);
                if (!ret) {
                    MEMCPY(socket.ip_addr, (u8 *)&params, 4); 
                }
                strcpy(socket.host_name, (char *)tmp);
            } else {
                if (socket.proto == 0) {
                    ret = string_to_uint((char *)tmp, &params);
                    if (ret || params > 10000000) {
                        err = 1;
                        break;
                    }
                    socket.timeout = params; 
					strcpy(socket.host_name, (char *)tmp);
                }
            }
            /* check port */
            ret = string_to_uint(tok->arg[3], &params);
            if (ret || (params > 0xFFFF)) {
                err = 1;
                break;
            }
            socket.port = params; 

            err = 0;
        } while (0);

        if (!err) {
            ret = tls_cmd_set_default_socket_params(&socket, update_flash);
            if (ret) {
                *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
            } else {
                *res_len = atcmd_ok_resp(res_resp);
            }
        } else {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
        } 
    } else {
        /* get automode socket info */
        memset(&socket, 0, sizeof(struct tls_cmd_socket_t));
        ret = tls_cmd_get_default_socket_params(&socket);
        *res_len = sprintf(res_resp, 
                "+OK=%u,%u,", socket.proto,
                socket.client ? 0 : 1);
        if (socket.client) {
			*res_len += sprintf(res_resp + (*res_len), "\"%s\"", socket.host_name);
        } else {
            if (socket.proto == 0) {
                /* TCP */
                *res_len += sprintf(res_resp + (*res_len),
                        "%d", socket.timeout);
            }
        }
        *res_len += sprintf(res_resp + (*res_len), ",%u", socket.port); 
    }
    return 0;
}

static int atcmd_aolm_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    if (tok->arg_found) {
        MEMCPY(res_resp, at_resp_err, AT_RESP_ERR_STR_LEN); 
        *res_len = AT_RESP_ERR_STR_LEN;
    } else {
        MEMCPY(res_resp, at_resp_ok, AT_RESP_OK_STR_LEN);
        *res_len = AT_RESP_OK_STR_LEN;
    }
    return 0;
}

static int atcmd_portm_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u8 mode;
    int ret = 0; 
    u32 param;
    u8 update_flash = 0;
    u8 set_opt = 0;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        if (ret || param > 3) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        } 
        mode = (u8)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_hostif_mode(mode, update_flash); 
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_hostif_mode(&mode); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else
            *res_len = sprintf(res_resp, "+OK=%u", mode);
    }
    return 0;
}

static int atcmd_uart_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    struct tls_cmd_uart_params_t uart_cfg;
    u8 update_flash = 0;
    u8 set_opt = 0;
    int err = 0;
    int ret;
    u32 params;

    if ((tok->op == ATCMD_OP_EP) && ((tok->arg_found == 4)||(tok->arg_found == 5))) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && ((tok->arg_found == 4)||(tok->arg_found == 5))){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        do {
            /* baud rate */
            ret = string_to_uint(tok->arg[0], &params);
            if (ret) {
                err = 1;
                break;
            }
            uart_cfg.baud_rate = params;
            /* char length */
            ret = string_to_uint(tok->arg[1], &params);
            if (ret) {
                err = 1;
                break;
            }
            uart_cfg.charlength = params;
            /* stopbit */
            ret = string_to_uint(tok->arg[2], &params);
            if (ret) {
                err = 1;
                break;
            }
            uart_cfg.stop_bit = params;
            /* parity */
            ret = string_to_uint(tok->arg[3], &params);
            if (ret) {
                err = 1;
                break;
            }
            uart_cfg.parity = params;
            /* flow control */
			if (tok->arg_found == 5){
	            ret = string_to_uint(tok->arg[4], &params);
	            if (ret) {
	                err = 5;
	                break;
	            }
	            uart_cfg.flow_ctrl = params;
			}else{
				uart_cfg.flow_ctrl = 0;
			}

            err = 0;
        } while (0);

        if (err) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0;
        }
        ret = tls_cmd_set_uart_params(&uart_cfg, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, ret);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_uart_params(&uart_cfg);
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else {
            *res_len = sprintf(res_resp, 
                    "+OK=%u,%u,%u,%u,%u",
                    uart_cfg.baud_rate, uart_cfg.charlength,
                    uart_cfg.stop_bit, uart_cfg.parity,
                    uart_cfg.flow_ctrl);
        }
    }
    return 0;    
}

static int atcmd_atlt_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u16 uart_atlt;
    u32 param;
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        
        if (ret || param > 1024 || param < 32) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        }
        uart_atlt = (u16)param;
    }

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    } 

    if (set_opt) {
        ret = tls_cmd_set_atlt((u16)uart_atlt, update_flash); 
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
        ret = tls_cmd_get_atlt(&uart_atlt); 
        if (ret)
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        else
            *res_len = sprintf(res_resp, "+OK=%u", uart_atlt);
    }
    return 0;
}

static int atcmd_dns_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    u16 dns_len;
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;
	u8 local_dnsname[32];
    u8 *dnsname=NULL;
    int err;

    if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
        set_opt = 1;
        update_flash = 1; 
    } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
        set_opt = 1;
        update_flash = 0;
    } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
        set_opt = 0;
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        return 0;
    }	

    if (set_opt) {
        err = atcmd_filter_quotation(&dnsname, (u8 *)tok->arg[0]);
        dns_len = strlen((char *)dnsname);
		if ((err > 0) || (dns_len > 31) || (dns_len == 0)){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		MEMCPY(local_dnsname, dnsname, dns_len);
		local_dnsname[dns_len] = '\0';
		ret = tls_cmd_set_dnsname(local_dnsname, update_flash);
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
        } else {
            *res_len = atcmd_ok_resp(res_resp);
        }
    } else {
       ret = tls_cmd_get_dnsname(local_dnsname);
	   if (ret)
		   *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	   else
		   *res_len = sprintf(res_resp, "+OK=\"%s\"", local_dnsname);

    }
    return 0;
}

static int atcmd_ddns_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    if (tok->arg_found) {
        MEMCPY(res_resp, at_resp_err, AT_RESP_ERR_STR_LEN); 
        *res_len = AT_RESP_ERR_STR_LEN;
    } else {
        MEMCPY(res_resp, at_resp_ok, AT_RESP_OK_STR_LEN);
        *res_len = AT_RESP_OK_STR_LEN;
    }
    return 0;
}

static int atcmd_upnp_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    if (tok->arg_found) {
        MEMCPY(res_resp, at_resp_err, AT_RESP_ERR_STR_LEN); 
        *res_len = AT_RESP_ERR_STR_LEN;
    } else {
        MEMCPY(res_resp, at_resp_ok, AT_RESP_OK_STR_LEN);
        *res_len = AT_RESP_OK_STR_LEN;
    }
    return 0;
}

static int atcmd_dname_proc( struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    if (tok->arg_found) {
        MEMCPY(res_resp, at_resp_err, AT_RESP_ERR_STR_LEN); 
        *res_len = AT_RESP_ERR_STR_LEN;
    } else {
        MEMCPY(res_resp, at_resp_ok, AT_RESP_OK_STR_LEN);
        *res_len = AT_RESP_OK_STR_LEN;
    }
    return 0;
}

static int atcmd_atpt_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
    u16 uart_atpt;
    u32 param;
    int ret = 0; 
    u8 update_flash = 0;
    u8 set_opt = 0;

    if (tok->arg_found == 1) {
        ret = string_to_uint(tok->arg[0], &param);
        
        if (ret || param > 10000 || param < 50) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        }
        uart_atpt = (u16)param;
    }


	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 } 
	
	 if (set_opt) {
		 ret = tls_cmd_set_atpt((u16)uart_atpt, update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 } else {
		 ret = tls_cmd_get_atpt(&uart_atpt); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else
			 *res_len = sprintf(res_resp, "+OK=%d", uart_atpt);
	 }

	 return 0;
}

static int atcmd_espc_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
	u32 EscapeChar;
	u32 param;
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;

	if (tok->arg_found == 1) {
		ret = strtohex(&param, tok->arg[0]);
		if ((ret < 0) || (param > 0xFF))
		{
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
		}
		EscapeChar = (u8)param;
	}

	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 } 
	
	 if (set_opt) {
		 ret = tls_cmd_set_espc((u8)EscapeChar, update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 } else {
		 ret = tls_cmd_get_espc((u8 *)&EscapeChar); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else
			 *res_len = sprintf(res_resp, "+OK=%02x", (u8)EscapeChar);
	 }

	 return 0;
}


static int atcmd_espt_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
	u16 EscapePeriod;
	int param;
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;
	struct tls_hostif *hif = tls_get_hostif();
	if (tok->arg_found == 1) {
		ret = strtodec(&param, tok->arg[0]);
		
		if (ret || (param > 10000)||(param<100)) {
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0; 
		}
		EscapePeriod = (u16)((param/100)*100);
		if (EscapePeriod < hif->escape_pt){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0; 
		}
	}

	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 } 
	
	 if (set_opt) {
		 ret = tls_cmd_set_espt(EscapePeriod, update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 } else {
		 ret = tls_cmd_get_espt(&EscapePeriod); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else
			 *res_len = sprintf(res_resp, "+OK=%d", EscapePeriod);
	 }

	 return 0;
}


static int atcmd_webs_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
	u32 param;
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;
	struct tls_webs_cfg stWebsCfg;
	
	if (tok->arg_found >= 1){
		ret = strtodec((int *)&param, tok->arg[0]);
	    if (ret || (param >1 )){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0; 
	    }
		stWebsCfg.AutoRun = (u8)param;
		stWebsCfg.PortNum = 80;
		
	}

	if (tok->arg_found >= 2){
		ret = strtodec((int *)&param, tok->arg[1]);
		if (ret || (param>65535)||(param == 0)){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		stWebsCfg.PortNum = (u16)param;
	}

	if ((tok->op == ATCMD_OP_EP) && ((tok->arg_found==1)||(tok->arg_found==2))) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ) && ((tok->arg_found==1)||(tok->arg_found==2))){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 }

	 if (set_opt){
		 ret = tls_cmd_set_webs( stWebsCfg , update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 }else{
		 ret = tls_cmd_get_webs(&stWebsCfg); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else{
			 if (stWebsCfg.AutoRun == 1)
				*res_len = sprintf(res_resp, "+OK=%d,%d",stWebsCfg.AutoRun, stWebsCfg.PortNum);
			 else
			 	*res_len = sprintf(res_resp, "+OK=%d", stWebsCfg.AutoRun);
		 }
	 }

	return 0;
}

static int atcmd_iom_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
	u8 iomode;
	u32 param;
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;

	if (tok->arg_found == 1) {
		ret = strtodec((int *)&param, tok->arg[0]);
		if ((ret < 0) || (param > 2))
		{
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
		}
		iomode = (u8)param;
	}

	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 } 
	
	 if (set_opt) {
		 ret = tls_cmd_set_iom((u8)iomode, update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 } else {
		 ret = tls_cmd_get_iom(&iomode); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else
			 *res_len = sprintf(res_resp, "+OK=%x", iomode);
	 }

	 return 0;

}

static int atcmd_cmdm_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
	u8 cmdm;
	u32 param;
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;

	if (tok->arg_found == 1) {
		ret = strtodec((int *)&param, tok->arg[0]);
		if ((ret < 0) || (param > 1))
		{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0; 
		}
		cmdm = (u8)param;
	}

	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 } 
	
	 if (set_opt) {
		 ret = tls_cmd_set_cmdm((u8)cmdm, update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 } else {
		 ret = tls_cmd_get_cmdm(&cmdm); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else
			 *res_len = sprintf(res_resp, "+OK=%d", cmdm);
	 }

	 return 0;
}
static int atcmd_set_oneshot_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len){
	u8 oneshotflag;
	u32 param;
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;

	if (tok->arg_found == 1) {
		ret = strtodec((int *)&param, tok->arg[0]);
		if ((ret < 0) || (param > 2))
		{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0; 
		}
		oneshotflag = (u8)param;
	}

	if ((tok->op == ATCMD_OP_EP) && (tok->arg_found == 1)) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ) && (tok->arg_found == 1)){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 } 
	
	 if (set_opt) {
		 ret = tls_cmd_set_oneshot(oneshotflag, update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 wm_cmdp_oneshot_task_init();
			 tls_netif_add_status_event(wm_cmdp_oneshot_status_event);	
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 } else {
		 ret = tls_cmd_get_oneshot(&oneshotflag); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else
			 *res_len = sprintf(res_resp, "+OK=%d", oneshotflag);
	 }

	 return 0;   
}

static int atcmd_pass_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
	u8 password[7];
	int ret = 0; 
	u8 update_flash = 0;
	u8 set_opt = 0;
	u8 *pwd;
	
	if (tok->arg_found == 1) {
		if (atcmd_filter_quotation(&pwd, (u8 *)tok->arg[0])){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		if (strlen((char *)pwd) != 6){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0; 
		}

		MEMCPY(password, pwd, 6);
	}

	if ((tok->op == ATCMD_OP_EP)&&(tok->arg_found == 1)) {
		 set_opt = 1;
		 update_flash = 1; 
	 } else if ((tok->op == ATCMD_OP_EQ)&&(tok->arg_found == 1)){
		 set_opt = 1;
		 update_flash = 0;
	 } else if ((tok->op == ATCMD_OP_QU)&&(tok->arg_found == 0)) {
		 set_opt = 0;
	 } else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
		 set_opt = 0;
	 } else {
		 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 return 0;
	 } 
	
	 if (set_opt) {
		 ret = tls_cmd_set_pass( password, update_flash); 
		 if (ret) {
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 } else {
			 *res_len = atcmd_ok_resp(res_resp);
		 }
	 } else {
	 	 password[6] = '\0';
		 ret = tls_cmd_get_pass(password); 
		 if (ret)
			 *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		 else
		 {
			*res_len = sprintf(res_resp, "+OK=\"%c%c%c%c%c%c\"", \
				password[0],password[1],password[2],\
				password[3],password[4],password[5]);
		 }
	 }

	 return 0;
}


static int atcmd_dbg_proc( struct tls_atcmd_token_t 
        *tok, char *res_resp, u32 *res_len)
{
    u32 dbg;
    int ret = 0; 

    if ((tok->arg_found == 1) && (tok->op == ATCMD_OP_EQ)) {
        ret = string_to_uint(tok->arg[0], &dbg);
        
        if (ret) {
            *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
            return 0; 
        }

        tls_cmd_set_dbg(dbg);
        *res_len = atcmd_ok_resp(res_resp);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }

    return 0;
}

static int atcmd_updp_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret, mode;
    if((1 != tok->arg_found) || (ATCMD_OP_EQ != tok->op))
   	{
   		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
    }
	ret = string_to_uint(tok->arg[0], (u32 *)&mode);
	if(ret) 
	{
		TLS_DBGPRT_ERR("updp param err! %x\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	if(1== mode)
	{
		extern struct tls_sys_param user_default_param;
		extern int tls_param_load_user(struct tls_sys_param *param);
		struct tls_sys_param *param = &user_default_param;
		
		tls_param_set_updp_mode(mode);
		tls_param_load_user(param);
	}
	else
	{
		tls_param_set_updp_mode(0);
		tls_param_save_user_default();
	}
	*res_len = atcmd_ok_resp(res_resp); 
    return 0;
}
#if TLS_CONFIG_HTTP_CLIENT_TASK
static int atcmd_http_client_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret, verb;
	u8 * uri;
	char * sndData = NULL;
	http_client_msg msg;
	if((2 > tok->arg_found) || (ATCMD_OP_EQ != tok->op))
   	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	ret = atcmd_filter_quotation(&uri,(u8 *)tok->arg[0]);
	if (ret){
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	ret = string_to_uint(tok->arg[1], (u32 *)&verb);
	if(ret) 
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	if(verb == VerbPost || verb == VerbPut)
	{
		if(3 > tok->arg_found) 
		{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		sndData = tok->arg[2];
	}
	memset(&msg, 0, sizeof(http_client_msg));
	msg.param.Uri = (CHAR *)uri;
	msg.method = (HTTP_VERB)verb;
	if(verb == VerbPost || verb == VerbPut)
	{
		msg.dataLen = strlen(sndData);
		msg.sendData = sndData;
	}
	msg.recv_fn = tls_hostif_http_client_recv_callback;
	msg.err_fn = tls_hostif_http_client_err_callback;
	http_client_post(&msg);
	*res_len = sprintf(res_resp, "+OK=%d", msg.pSession);
	return 0;
}
#endif
#endif

static int atcmd_custdata_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u8 *data = NULL;
	if (tok->op != ATCMD_OP_QU)
	{
   		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}else{
	    data = tls_mem_alloc(65);
		if (data){
			memset(data, 0, 65);
			tls_wifi_get_customdata(data);
			*res_len = sprintf(res_resp, "+OK=%s", data);
			tls_mem_free(data);
			data = NULL;
			return 0;
		}else{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_MEM);
			return 0;
		}
	}
}

static int atcmd_mac_proc( 
	struct tls_atcmd_token_t *tok, 
	char *res_resp, u32 *res_len)
{
	u8 *mac = NULL;
	u8 *tmpmac = NULL;

	if (!tok->arg_found && 
		((tok->op == ATCMD_OP_NULL) || (tok->op == ATCMD_OP_QU))) 
	{
		mac = wpa_supplicant_get_mac();
		*res_len = sprintf(res_resp, "+OK=%02x%02x%02x%02x%02x%02x", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); 
	} 
	else if (tok->arg_found &&((tok->op == ATCMD_OP_EP)||(tok->op== ATCMD_OP_EQ)))
	{
		if (atcmd_filter_quotation(&tmpmac, (u8 *)tok->arg[0])){
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		}

		mac = tls_mem_alloc(ETH_ALEN);		
		if (mac){
			if (strtohexarray(mac, ETH_ALEN, (char *)tmpmac)< 0){
				*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
			}else{
				wpa_supplicant_set_mac(mac);
				tls_set_mac_addr(mac);
				*res_len = atcmd_ok_resp(res_resp);
			}
			tls_mem_free(mac);
			mac = NULL;
		}else{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		}
	}
	else
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}
	return 0;
}

static int atcmd_ver_proc( 
        struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
	struct tls_cmd_ver_t ver;
	    
	if (!tok->arg_found && 
		((tok->op == ATCMD_OP_NULL) || (tok->op == ATCMD_OP_QU))) 
	{
		tls_cmd_get_ver(&ver);
		*res_len = sprintf(res_resp, "+OK=%c%x.%02x.%02x.%02x%02x,%c%x.%02x.%02x@ %s %s",
                ver.hw_ver[0], ver.hw_ver[1], ver.hw_ver[2],
                ver.hw_ver[3], ver.hw_ver[4], ver.hw_ver[5],
                ver.fw_ver[0], ver.fw_ver[1], ver.fw_ver[2],
                ver.fw_ver[3],SysCreatedTime, SysCreatedDate);
	} 
	else 
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}

    return 0;
}


static int atcmd_updm_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret, mode;
	
    if((1 != tok->arg_found) || (ATCMD_OP_EQ != tok->op))
   	{
   		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
    }
	ret = string_to_uint(tok->arg[0], (u32 *)&mode);
	TLS_DBGPRT_INFO("kevin mode = %x\r\n", mode);
	if(ret) 
	{
		TLS_DBGPRT_INFO("kevin err! %x\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	if(0 == tls_get_fwup_mode())
	{
		if(1 == mode)
		{
			tls_set_fwup_mode(mode);
			tls_cmd_disconnect_network();/*升级时断开网络*/
			tls_fwup_enter(TLS_FWUP_IMAGE_SRC_LUART);
		}
	}
	else
	{
		if(0 == mode)
		{
			tls_set_fwup_mode(0);
			tls_fwup_exit(tls_fwup_get_current_session_id());
		}
	}
	*res_len = atcmd_ok_resp(res_resp); 
    return 0;
}

static int atcmd_updd_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
    int ret, datasize, session_id;
	cmd_set_uart1_mode_callback callback;
	struct tls_hostif *hif = tls_get_hostif();
	
    if(1 != tok->arg_found)
   	{
   		TLS_DBGPRT_INFO("kevin arg_found err! %x\r\n", tok->arg_found);
   		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
    }
	
	ret = string_to_uint(tok->arg[0], (u32 *)&datasize);
	if(ret || (datasize != sizeof(struct tls_fwup_block))) 
	{
		TLS_DBGPRT_INFO("kevin datasize err! %x, %x, %x\r\n", tok->arg[0], ret, datasize);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	session_id = tls_fwup_get_current_session_id();
	if((0 == session_id) || (TLS_FWUP_STATUS_OK != tls_fwup_current_state(session_id)))
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	if(tok->cmd_mode == CMD_MODE_UART1_ATCMD)
	{
		callback = tls_cmd_get_set_uart1_mode();
		if(callback!=NULL)
			callback(UART_ATDATA_MODE);
	}else if (tok->cmd_mode == CMD_MODE_UART0_ATCMD){
		callback = tls_cmd_get_set_uart0_mode();
		if (callback != NULL)
			callback(UART_ATDATA_MODE);

	}
	*res_len = sprintf(res_resp, "+OK=%d", tls_fwup_get_current_update_numer());
    return 0;
}

/******************************************************************
* Description:	Read register or memory

* Format:		AT+&REGR=<address>,[num]<CR>
			+OK=<value1>,[value2]...<CR><LF><CR><LF>
		
* Argument:	address: num:

* Author: 	kevin 2014-03-19
******************************************************************/
static int atcmd_regr_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret;
	u32 Addr, Num, Value;
	u8 buff[16];
	
	if(2 != tok->arg_found) 
	{
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	}	
    	ret = hexstr_to_uinit(tok->arg[0], &Addr);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x,\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	ret = hexstr_to_uinit(tok->arg[1], &Num);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x,\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	Value = tls_reg_read32(Addr);
	TLS_DBGPRT_INFO("Addr = %x, Value = 0x%x,\r\n", Addr, Value);
	*res_len = sprintf(res_resp, "+OK=%08x", Value);
	memset(buff, 0, sizeof(buff));
	while(--Num)
	{
		Addr += 4;
		Value = tls_reg_read32(Addr);
		*res_len += sprintf((char *)buff, ",%08x", Value);
		strcat(res_resp, (char *)buff);
	}
	return 0;
}

/******************************************************************
* Description:	Write register or memory

* Format:		AT+&REGW=<address>,<value1>,[value2]...<CR>
			+OK=<CR><LF><CR><LF>
		
* Argument:	address: value:

* Author: 	kevin 2014-03-19
******************************************************************/
static int atcmd_regw_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret;
	u32 Addr, Value, i;
	
	if((tok->arg_found < 2) || (tok->arg_found > 9))
	{
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[0], &Addr);
	if(ret)
	{
		TLS_DBGPRT_INFO("Addr ret = 0x%x,\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	for(i = 0; i < tok->arg_found - 1; i++)
	{
		ret = hexstr_to_uinit(tok->arg[i+1], &Value);
		if(ret)
		{
			TLS_DBGPRT_INFO("Value ret = 0x%x,\r\n", ret);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		else
		{
			TLS_DBGPRT_INFO("Addr = %x, Value = 0x%x,\r\n", Addr, Value);
			tls_reg_write32(Addr, Value);
		}
		Addr += 4;
	}
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

/******************************************************************
* Description:	Read RF register

* Format:		AT+&RFR=<address>,[num]<CR>
			+OK=<value1>,[value2]...<CR><LF><CR><LF>
		
* Argument:	address: size:

* Author: 	kevin 2014-03-19
******************************************************************/
static int atcmd_rfr_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret, i;
	u32 Addr, Num;
	u8 buff[16];
	u16 databuf[8], *pdatabuf;
	
	if(2 != tok->arg_found) 
	{
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	}	
    	ret = hexstr_to_uinit(tok->arg[0], &Addr);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x,\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	ret = hexstr_to_uinit(tok->arg[1], &Num);
	if(ret || (Num < 1) || (Num > 8) || (Addr+Num) > 25)
	{
		TLS_DBGPRT_INFO("ret = 0x%x,\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	for(i = 0; i < Num; i++)
	{
		databuf[i] = (u16)hed_rf_read(Addr);
		Addr += 1;
	}
	*res_len = sprintf(res_resp, "+OK=%04x", databuf[0]);
	pdatabuf = &databuf[1];
	while(--Num)
	{
		*res_len += sprintf((char *)buff, ",%04x", *pdatabuf++);
		strcat(res_resp, (char *)buff);
	}
	return 0;
}

/******************************************************************
* Description:	Write RF registers

* Format:		AT+&RFW=<address>,<value1>,[value2]...<CR>
			+OK<CR><LF><CR><LF>
		
* Argument:	address: value:

* Author: 	kevin 2014-03-19
******************************************************************/
static int atcmd_rfw_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret, i;
	u32 Addr, Num, Value;
	u16 databuf[8];
	
	if((tok->arg_found < 2) || (tok->arg_found > 9)) 
	{
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	}	
    ret = hexstr_to_uinit(tok->arg[0], &Addr);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x,\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	Num = 0;
	for(i = 0; i < tok->arg_found - 1; i++)
	{
		ret = hexstr_to_uinit(tok->arg[i+1], &Value);
		if(ret)
		{
			TLS_DBGPRT_INFO("Value ret = 0x%x,\r\n", ret);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		else
		{
			TLS_DBGPRT_INFO("Value = 0x%x,\r\n", Value);
			databuf[Num++] = Value;
		}
	}
	if((Num < 1) || (Num > 8) || (Addr+Num) > 25)
	{
		TLS_DBGPRT_INFO("ret = 0x%x,\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	Addr = Addr*2;
	for(i = 0; i < Num; i++)
	{
		hed_rf_write((Addr << 16) | databuf[i]);
		Addr += 2;
	}
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

static int atcmd_flsr_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u32 addr, len, ret, i;
	u8 buff[32];
	u8 temp[16];
	
	if(tok->arg_found < 2)
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[0], &addr);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x, addr = 0x%x\r\n", ret, addr);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[1], &len);
	if(ret || (len > 8) || (len < 1))
	{
		TLS_DBGPRT_INFO("ret = 0x%x, len = 0x%x\r\n", ret, len);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	TLS_DBGPRT_INFO("addr = 0x%x, len = 0x%x\r\n", addr, len);
	
	memset(buff, 0, sizeof(buff));
	ret = tls_fls_read(addr, buff, 4 * len);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	*res_len = sprintf(res_resp, "+OK=%08x", *((u32 *)(&buff[0])));
	for(i = 1; i < len; i++)
	{
		sprintf((char *)temp, ",%08x", *((u32 *)(&buff[i * 4])));
		strcat(res_resp, (char *)temp);
		*res_len += 9;
	}
    return 0;
}

static int atcmd_flsw_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{ 
	u32 addr, num, data, ret, i;
	u8 buff[32];
	
	if((tok->arg_found < 2) || (tok->arg_found > 9))
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
		return 0;
	}
	num = tok->arg_found - 1;
	
	ret = hexstr_to_uinit(tok->arg[0], &addr);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x, addr = 0x%x\r\n", ret, addr);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	TLS_DBGPRT_INFO("addr = 0x%x, num = 0x%x\r\n", addr, num);

	memset(buff, 0, sizeof(buff));
	for(i = 0; i < num; i++)
	{
		hexstr_to_uinit(tok->arg[i + 1], &data);
		MEMCPY(&buff[4 * i], &data, sizeof(u32));
		TLS_DBGPRT_INFO("data = 0x%x\r\n", data);
	}
	
	ret = tls_fls_write(addr, buff, 4 * num);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	*res_len = atcmd_ok_resp(res_resp);
    return 0;
}

/******************************************************************
* Description:	set/get system tx gain

* Format:		AT+&TXG=[!?][gain]<CR>
			+OK[=gain]<CR><LF><CR><LF>
		
* Argument:	12 byte hex ascii

* Author: 	kevin 2014-03-12
******************************************************************/
static int atcmd_txg_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{ 
	int i,j;
	u8* tx_gain = ieee80211_get_tx_gain();
	if ((0 == tok->arg_found) && ((ATCMD_OP_NULL == tok->op) || (ATCMD_OP_QU == tok->op))) 
	{// get tx gain
		for (i = 0; i < 29; i++)
		{
			for (j = 0; j < 31; j++){
				if (tx_gain[i] == hed_rf65_txgainmap[j])
				{
					tx_gain[i] = j;
					break;
				}
			}
		}
	*res_len = sprintf(res_resp, "+OK=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
	"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
	"%02x%02x%02x%02x%02x", \
		tx_gain[0], tx_gain[1], tx_gain[2], \
		tx_gain[3], tx_gain[4], tx_gain[5], \
		tx_gain[6], tx_gain[7], tx_gain[8], \
		tx_gain[9], tx_gain[10], tx_gain[11],\
		tx_gain[12], tx_gain[13], tx_gain[14],\
		tx_gain[15], tx_gain[16], tx_gain[17],\
		tx_gain[18], tx_gain[19], tx_gain[20],\
		tx_gain[21], tx_gain[22], tx_gain[23],\
		tx_gain[24], tx_gain[25], tx_gain[26],\
		tx_gain[27], tx_gain[28]);
				}
	else if((1 == tok->arg_found) && ((ATCMD_OP_EQ == tok->op) || ((ATCMD_OP_EP == tok->op))))
	{// set tx gain
		if (strtohexarray(tx_gain, 29, tok->arg[0]) < 0)
		{
			TLS_DBGPRT_INFO("kevin TxGain err!\r\n");
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		for(i=0; i<29; i++)
		{
			if (tx_gain[i] > 30)
			{
				TLS_DBGPRT_INFO("kevin TxGain err %d, %x\r\n", i, tx_gain[i]);
				*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
				return 0;
			}
			tx_gain[i] = hed_rf65_txgainmap[tx_gain[i]]; 		/*转换序号为实际增益值*/
		}
		// save tx gain
		if(ATCMD_OP_EP == tok->op)
		{
			TLS_DBGPRT_INFO("save tx gain!\r\n");
			tls_efuse_write(TLS_EFUSE_TXGAIN_BG_OFFSET, &tx_gain[0], 12);
			tls_efuse_write(TLS_EFUSE_TXGAIN_MCS_OFFSET, &tx_gain[12], 17);
		}
		*res_len = atcmd_ok_resp(res_resp); 

	}
	else
	{	
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}
	return 0;
}

/******************************************************************
* Description:	get hardware version

* Format:		AT+&HWV=[?][ver]<CR>
			+OK[=ver]<CR><LF><CR><LF>
		
* Argument:	6 byte version

* Author: 	kevin 2014-03-12
******************************************************************/
static int atcmd_hwv_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	struct tls_cmd_ver_t ver;

	if ((0 ==tok->arg_found) && ((ATCMD_OP_NULL == tok->op) || (ATCMD_OP_QU == tok->op))) 
	{// get hardware version
		tls_cmd_get_ver(&ver);
		*res_len = sprintf(res_resp, "+OK=%02x%02x%02x%02x%02x%02x", \
			ver.hw_ver[0], ver.hw_ver[1], ver.hw_ver[2], \
			ver.hw_ver[3], ver.hw_ver[4], ver.hw_ver[5]);
	}  
	else
	{	
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}
	return 0;
}

/******************************************************************
* Description:	set&&get hardware version (PCB version)

* Format:		AT+&RWHWV=[?][ver]<CR>
			+OK[=ver]<CR><LF><CR><LF>
		
* Argument:	6 byte version

* Author: 	cui 2015-06-29
******************************************************************/
static int atcmd_rwhwv_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	struct tls_cmd_ver_t ver;
	u8 *verinfo = NULL;
	int i = 0;
	int j = 0;

	if ((0 ==tok->arg_found) && ((ATCMD_OP_NULL == tok->op) || (ATCMD_OP_QU == tok->op))) 
	{// get hardware version
		tls_cmd_get_hw_ver(ver.hw_ver);
		*res_len = sprintf(res_resp, "+OK=%c%d.%d%d.%d%d", \
			ver.hw_ver[0], ver.hw_ver[1], ver.hw_ver[2], \
			ver.hw_ver[3], ver.hw_ver[4], ver.hw_ver[5]);
	}  
	else if ((1 == tok->arg_found)&&((ATCMD_OP_EP == tok->op) || (ATCMD_OP_EQ == tok->op)))
	{
		atcmd_filter_quotation(&verinfo, (u8 *)(tok->arg[0]));
		ver.hw_ver[0] = verinfo[0];
		j++;
		for (i = 1; i < strlen((char *)verinfo); i++){
			if (verinfo[i] != '.'){
				ver.hw_ver[j] = atodec(verinfo[i]);
				j++;
			}
		}

		if ((ver.hw_ver[0] != 'V')&&(ver.hw_ver[0] != 'v'))
		{
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		}else{
			tls_cmd_set_hw_ver(ver.hw_ver);
			*res_len = sprintf(res_resp, "+OK");
		}
	}
	else
	{	
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}
	return 0;
}


/******************************************************************
* Description:	Set/Get spi flash's parameter

* Format:		AT+&SPIF=[!?][size]<CR>[data stream]
			+OK<CR><LF><CR><LF>[data stream]
		
* Argument:	hex

* Author: 	kevin 2014-03-17
******************************************************************/
static int atcmd_spif_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u8 buff[32];
	int ret, len;
	
	if ((1 == tok->arg_found) && ((ATCMD_OP_NULL == tok->op) || (ATCMD_OP_QU == tok->op))) 
	{
		ret = string_to_uint(tok->arg[0], (u32 *)&len);
		if (ret || (len > TLS_EFUSE_SPIFLASH_PARAM_SIZE)) 
		{
			TLS_DBGPRT_INFO("kevin len err! %x, %x\r\n", ret, len);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		memset(buff, 0, sizeof(buff));
		tls_efuse_read(TLS_EFUSE_SPIFLASH_PARAM_OFFSET, buff, len);
		*res_len = sprintf(res_resp, "+OK=%s", buff);
	}  
	else if((2 == tok->arg_found) && ((ATCMD_OP_EQ == tok->op) || ((ATCMD_OP_EP == tok->op))))
	{
		ret = string_to_uint(tok->arg[0], (u32 *)&len);
		if (ret || (len > TLS_EFUSE_SPIFLASH_PARAM_SIZE)) 
		{
			TLS_DBGPRT_INFO("kevin len err! %x, %x\r\n", ret, len);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		memset(buff, 0, sizeof(buff));
		if (strtohexarray(buff, len, tok->arg[1]) < 0)
		{
			TLS_DBGPRT_INFO("kevin buff err!\r\n");
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		tls_efuse_write(TLS_EFUSE_TXGAIN_BG_OFFSET, buff, len);
		*res_len = atcmd_ok_resp(res_resp); 
	}
	else
	{
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}
	return 0;
}
/******************************************************************
* Description:	For litepoint init

* Format:		
		
* Argument:	none

* Author: 	kevin 2014-03-13
******************************************************************/
static void atcmd_lpinit(void)
{
	if (!g_ltpt_testmode)
	{
		g_ltpt_testmode = TRUE;
	}

}
/******************************************************************
* Description:	For litepoint test, set wireless channel

* Format:		AT+&LPCHL=[!?]<channel><CR>
			+OK<CR><LF><CR><LF>
		
* Argument:	channel:1-14

* Author: 	kevin 2014-03-12
******************************************************************/
static int atcmd_lpchl_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	int ret;
	u8 Channel, channel_en;

	if ((0 == tok->arg_found) && ((ATCMD_OP_NULL == tok->op) || (ATCMD_OP_QU == tok->op))) 
	{// get channel
		ret = tls_cmd_get_channel(&Channel, &channel_en);
		*res_len = sprintf(res_resp, "+OK=%d", Channel);
	}  
	else if((1 == tok->arg_found) && (ATCMD_OP_EQ == tok->op) )
	{// set channel

		ret = string_to_uint(tok->arg[0], (u32 *)&Channel);
		if (ret || (Channel < 1)|| (Channel > 14)) 
		{
			TLS_DBGPRT_INFO("kevin params err! %x, %x\r\n", ret, Channel);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		atcmd_lpinit();
		//config channel
		tls_wifi_change_chanel((Channel-1));
		*res_len = atcmd_ok_resp(res_resp);
	}
	else
	{
		TLS_DBGPRT_INFO("kevin option err!\r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
	}
	return 0;
}

/******************************************************************
* Description:	For litepoint test, start tx process

* Format:		AT+&LPTSTR=<Channel>,<PacketCount>,<PsduLen>,<TxGain>,<DataRate><CR>
			+OK<CR><LF><CR><LF>
		
* Argument:	hex <Channel>,<PacketCount>,<PsduLen>,<TxGain>,<DataRate>
			
* Author: 	kevin 2014-03-13
******************************************************************/
static int atcmd_lptstr_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u32 Channel = 1;
	u32 PacketCount = 10;
	u32 PsduLen = 100;
	u32 TxGain = 0;
	u32 DataRate;	
	int TxRate;
	int ret;
	
	if(5 != tok->arg_found)
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[0], &Channel);/*Channel is not used*/
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x, Channel = 0x%x \r\n", ret, Channel);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[1], &PacketCount);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x, PacketCount = 0x%x \r\n", ret, PacketCount);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[2], &PsduLen);
	if(ret || (PsduLen < 24) || (PsduLen > 1600))
	{
		TLS_DBGPRT_INFO("ret = 0x%x, PsduLen = 0x%x \r\n", ret, PsduLen);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[3], &TxGain);
	if(ret || (TxGain > 30))
	{
		TLS_DBGPRT_INFO("ret = 0x%x, TxGain = 0x%x \r\n", ret, TxGain);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[4], &DataRate);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x, DataRate = 0x%x \r\n", ret, DataRate);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	TLS_DBGPRT_INFO("Channel = 0x%x, PacketCount = 0x%x, PsduLen = 0x%x, TxGain = 0x%x, DataRate = 0x%x \r\n", Channel, PacketCount, PsduLen, TxGain, DataRate);
	switch(DataRate)
	{
		case S2M:
			TxRate = TLS_PARAM_TX_RATEIDX_2M;
			break;
		case S5M5:
			TxRate = TLS_PARAM_TX_RATEIDX_5_5M;
			break;
		case S11M:
			TxRate = TLS_PARAM_TX_RATEIDX_11M;
			break;
		case L1M:
			TxRate = TLS_PARAM_TX_RATEIDX_1M;
			break;
		case L2M:
			TxRate = TLS_PARAM_TX_RATEIDX_2M;
			break;
		case L5M5:
			TxRate = TLS_PARAM_TX_RATEIDX_5_5M;
			break;
		case L11M:
			TxRate = TLS_PARAM_TX_RATEIDX_11M;
			break;
		case R06M:
			TxRate = TLS_PARAM_TX_RATEIDX_6M;
			break;
		case R09M:
			TxRate = TLS_PARAM_TX_RATEIDX_9M;
			break;
		case R12M:
			TxRate = TLS_PARAM_TX_RATEIDX_12M;
			break;
		case R18M:
			TxRate = TLS_PARAM_TX_RATEIDX_18M;
			break;
		case R24M:
			TxRate = TLS_PARAM_TX_RATEIDX_24M;
			break;
		case R36M:
			TxRate = TLS_PARAM_TX_RATEIDX_36M;
			break;
		case R48M:
			TxRate = TLS_PARAM_TX_RATEIDX_48M;
			break;
		case R54M:
			TxRate = TLS_PARAM_TX_RATEIDX_54M;
			break;
			
		case MCS0:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS0;
			break;			
		case MCS1:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS1;
			break;			
		case MCS2:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS2;
			break;			
		case MCS3:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS3;
			break;			
		case MCS4:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS4;
			break;			
		case MCS5:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS5;
			break;			
		case MCS6:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS6;
			break;			
		case MCS7:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS7;
			break;			
		case MCS8:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS8;
			break;
		case MCS9:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS9;
			break;
		case MCS10:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS10;
			break;
		case MCS11:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS11;
			break;
		case MCS12:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS12;
			break;
		case MCS13:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS13;
			break;
		case MCS14:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS14;
			break;
		case MCS15:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS15;
			break;
		case MCS32:
			TxRate = TLS_PARAM_TX_RATEIDX_MCS32;
			break;			
		default:
			TxRate = TLS_PARAM_TX_RATEIDX_6M;
			break;		
	}
	atcmd_lpinit();
	memset(&g_ltpt_txinfo, 0, sizeof(ltpt_tx_info));
	g_ltpt_txinfo.packetcount = PacketCount;
	g_ltpt_txinfo.psdulen = PsduLen;
	g_ltpt_txinfo.txgain = hed_rf65_txgainmap[TxGain];
	g_ltpt_txinfo.datarate = TxRate;
	g_ltpt_txinfo.bprocess = TRUE;
	g_ltpt_txinfo.channel = Channel;
	tls_tx_send_litepoint();
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

/******************************************************************
* Description:	For litepoint test, stop tx process

* Format:		AT+&LPTSTP<CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-13
******************************************************************/
static int atcmd_lptstp_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	g_ltpt_txinfo.bprocess = FALSE;
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

/******************************************************************
* Description:	For litepoint test, query tx infomation

* Format:		AT+&LPTSTT<CR>
			+OK=<TransCnt><CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-13
******************************************************************/
static int atcmd_lptstt_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	*res_len = sprintf(res_resp, "+OK=%x", g_ltpt_txinfo.cnt_total);
	return 0;
}

/******************************************************************
* Description:	For litepoint test, start rx process

* Format:		AT+&LPRSTR=channel<CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	channel:1-14
			
* Author: 	kevin 2014-03-13
******************************************************************/
static int atcmd_lprstr_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u32 Channel = 1;
	int ret;
	
	if(1 != tok->arg_found)
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	
	ret = hexstr_to_uinit(tok->arg[0], &Channel);
	if(ret || (Channel < 1) || (Channel > 14))
	{
		TLS_DBGPRT_INFO("ret = 0x%x, Channel = 0x%x \r\n", ret, Channel);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	atcmd_lpinit();
	//config channel
	tls_wifi_change_chanel((Channel-1));
	*res_len = atcmd_ok_resp(res_resp); 
	
	memset(&g_ltpt_rxinfo, 0, sizeof(ltpt_rx_info));
	g_ltpt_rxinfo.bprocess = TRUE;
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

/******************************************************************
* Description:	For litepoint test, stop rx process

* Format:		AT+&LPRSTP<CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-13
******************************************************************/
static int atcmd_lprstp_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	g_ltpt_rxinfo.bprocess = FALSE;
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

/******************************************************************
* Description:	For litepoint test, query rx infomation

* Format:		AT+&LPRSTT<CR>
			+OK=<TotalRecvCnt>,<CorrectRecvCnt>,<FcsErrorCnt><CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-13
******************************************************************/
static int atcmd_lprstt_proc( struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	*res_len = sprintf(res_resp, "+OK=%x,%x,%x", \
		g_ltpt_rxinfo.cnt_total, g_ltpt_rxinfo.cnt_good, g_ltpt_rxinfo.cnt_bad);
	return 0;
}

/******************************************************************
* Description:	For litepoint test, start the calibration process of rf's parameter(LO-Leakage)

* Format:		AT+&LPPSTR=<init_param>,<flag_start><CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	hex init_param: flag_start: 
			
* Author: 	kevin 2014-03-14
******************************************************************/
u8 gulCalFlag = 0;
static int atcmd_lppstr_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u32 tmp_param1, flag_start;
	signed short init_param;
	int ret;
	
	if((2 != tok->arg_found)&&(0!= tok->arg_found))
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	if (2 == tok->arg_found){
		ret = hexstr_to_uinit(tok->arg[0], &tmp_param1);
		if(ret)
		{				 
			TLS_DBGPRT_INFO("ret = 0x%x\r\n", ret);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		if(tmp_param1 & 0x8000)
		{
			init_param = (signed short)(tmp_param1 - 65536);
		}
		else
		{
			init_param = (signed short) tmp_param1;
		}
		
		ret = hexstr_to_uinit(tok->arg[1], &flag_start);
		if(ret)
		{
			TLS_DBGPRT_INFO("ret = 0x%x\r\n", ret);
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			return 0;
		}
		gulCalFlag = 0;
		*res_len = atcmd_ok_resp(res_resp);
	}else{
		flag_start = 1;
		init_param = -1;
		gulCalFlag = 1;
	}
	//当为1时表示是开始进行校正，此时将校正相关参数清零
	if(flag_start) 
	{
		hed_rf65_lo_leakage(init_param, TRUE);
	}
	hed_rf65_lo_leakage(init_param, FALSE) ;

	if (gulCalFlag){
	    *res_len = sprintf(res_resp, "+OK=%x", hed_rf_read(11));
	}

	return 0;
}

/******************************************************************
* Description:	For litepoint test, stop the calibration and return the result (IQ-Mismatch)

* Format:		AT+&LPPSTP=<result_param><CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	hex result_param: IQ-Mismatch
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lppstp_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u32 res;
	u32 mismatch = 0;
	int ret;

	if(1 != tok->arg_found)
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}

	ret = hexstr_to_uinit(tok->arg[0], &mismatch);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	if(mismatch & 0xFFFFC000)
	{
		TLS_DBGPRT_INFO("mismatch \r\n");
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}

	res = (mismatch << 16)|0x80000000; /* indicate flag, bit31:30: '10' */
	if (gulCalFlag){
		res += hed_rf_read(11)&0XFFFF;
	}else{
		res += hed_rf65_lo_leakage(0, TRUE);
	}
	tls_efuse_write(TLS_EFUSE_LOLEAKAGE_OFFSET, (INT8U *)&res, 4);
	//reconfig iqmismatch
	tls_reg_write32(0x0E000B04,mismatch);
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

/******************************************************************
* Description:	For litepoint test, setting the parameter of RF

* Format:		AT+&LPRFPS=< rftype ><size><CR>[data stream] 
			+OK=<CR><LF><CR><LF>
			
* Argument:	ftype：rf类型 0：2230；1：2829；2：HEDrf
              	data stream 中包含36个rf寄存器，和28个信道寄存器
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lprfps_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	/* not used */
	*res_len = atcmd_ok_resp(res_resp);
	return 0;
}

/******************************************************************
* Description:	For litepoint test,  receive and set channel

* Format:		AT+&LPCHRS =<channel>,< rxcbw ><CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	channel: 无线信道号，有效范围1～14
            		rxcbw: 接收对应信道带宽0:  20M；1：40M
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lpchrs_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	u32 channel = 0;
	int ret;

	if(1 != tok->arg_found)
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}

	ret = hexstr_to_uinit(tok->arg[0], &channel);
	if(ret)
	{
		TLS_DBGPRT_INFO("ret = 0x%x\r\n", ret);
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	sprintf(tok->arg[0], "%d", channel);
	return atcmd_lpchl_proc(tok, res_resp, res_len);
}

/******************************************************************
* Description:	For litepoint test,  BD Tx process

* Format:		AT+&LPTBD =< psdulen >,< txgain >,< datarate >< txcbw >,<gi>,<gf>,< rifs ><CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	psdulen: 数据长度，有效范围14～65535
			txgain: 发射增益
			datarate: 数据数率
			txcbw: 发射带宽0:20M;1:40M
			gi:  0:normal gi;1:short gi
			gf:  0:no green field;1: green field
			rifs:  0:no rifs;1:rifs
			Data Rate: 
			S2M = 0x0000, S5.5M = 0x0001, S11M = 0x0002, L1M = 0x0003,
			L2M = 0x0004, L5M5 = 0x0005, L11M = 0x0006, 06M = 0x0100,
			09M = 0x0101, 12M = 0x0102, 18M = 0x0103, 24M = 0x0104,
			36M = 0x0105, 48M = 0x0106, 54M = 0x0107, MCS0 = 0x200,
			MCS1 = 0x201, MCS2 = 0x202, MCS3 = 0x203, MCS4 = 0x204,
			MCS5 = 0x205, MCS6 = 0x206, MCS7 = 0x207,
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lptbd_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	char *arg_psdulen, *arg_datarate, *arg_txgain;
	
	if(7 != tok->arg_found)
	{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
		return 0;
	}
	arg_psdulen = tok->arg[0];
	arg_txgain = tok->arg[1];
	arg_datarate = tok->arg[2];

	tok->arg[0] = "1"; /* not used */
	tok->arg[1] = "0"; /* always */
	tok->arg[2] = arg_psdulen;
	tok->arg[3] = arg_txgain;
	tok->arg[4] = arg_datarate;
	tok->arg_found = 5;
	
	return atcmd_lptstr_proc(tok, res_resp, res_len);
}

/******************************************************************
* Description:	For litepoint test,  stop tx process

* Format:		AT+&LPSTPT<CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lpstpt_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	return atcmd_lptstp_proc(tok, res_resp, res_len);
}

/******************************************************************
* Description:	For litepoint test, receive channel

* Format:		AT+&LPCHLR =<channel>,< rxcbw ><CR>
			+OK<CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lpchlr_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	return atcmd_lprstr_proc(tok, res_resp, res_len);
}

/******************************************************************
* Description:	For litepoint test,  stop rx process

* Format:		AT+&LPSTPR<CR>
			+OK<CR><LF><CR><LF>
	
* Argument:	
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lpstpr_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	return atcmd_lprstp_proc(tok, res_resp, res_len);
}

/******************************************************************
* Description:	For litepoint test, For query rx frame information

* Format:		AT+&LPRAGC <CR>
			+OK=<TotalRecvCnt>,<CorrectRecvCnt>,<FcsErrorCnt><CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lpragc_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	return atcmd_lprstt_proc(tok, res_resp, res_len);
}

/******************************************************************
* Description:	For litepoint test,  For query rx frame information

* Format:		AT+&LPRSR [=?]<CR>
			+OK[=valid,rcpi,snr]<CR><LF><CR><LF>
			
* Argument:	
			
* Author: 	kevin 2014-03-14
******************************************************************/
static int atcmd_lprsr_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len)
{
	if (g_ltpt_rxinfo.valid)
	{
		*res_len = sprintf(res_resp, "+OK=%d,%x,%x", g_ltpt_rxinfo.valid, g_ltpt_rxinfo.rcpi, g_ltpt_rxinfo.snr);
	}
	else
	{
		*res_len = sprintf(res_resp, "+OK=%d", g_ltpt_rxinfo.valid);
	}
	return 0;
}

/*
For PIN:
1:
Step1:	   AT+WWPS=get_pin
		   Pin code will be responsed; User should input this Pin to AP; 
Step2: 	   AT+WWPS=start _pin
___________________________ 
2:
Step1: 	  AT+WWPS=!set_pin,xxxx
		  User can set an Pin code to device; User should input this Pin to AP ;
Step2: 	  AT+WWPS=start _pin

___________________________	
3: 	
Step1: 	  AT+WWPS=start _pin
		  Pin code is the default value, and stored in system during manufacturing;User should input this Pin to AP;

For PBC:
Step1:	 AT+WWPS=start_pbc

*/
	
#if TLS_CONFIG_WPS
static int atcmd_wps_proc(struct tls_atcmd_token_t *tok, 
			char *res_resp, u32 *res_len)
{
	struct tls_cmd_wps_params_t wps;
	struct tls_param_wps tmp_wps;
	int ret = 0;
	u8 update_flash = 0;
	u8 set_opt = 0;
	int len, i;
	int err = 0;

	
	
		if ((tok->op == ATCMD_OP_EP) && 
				((tok->arg_found == 1) || (tok->arg_found == 2))) {
			set_opt = 1;
			update_flash = 1; 
		} else if ((tok->op == ATCMD_OP_EQ) && 
				((tok->arg_found == 2) || (tok->arg_found == 1))){
			set_opt = 1;
			update_flash = 0;
		} else if ((tok->op == ATCMD_OP_QU) && (tok->arg_found == 0)) {
			set_opt = 0;
		} else if ((tok->op == ATCMD_OP_NULL) && (tok->arg_found == 0)) {
			set_opt = 0;
		} else {
			*res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
			return 0;
		} 
	
		if (set_opt) {
			do {
				if(!strcmp(tok->arg[0], "get_pin")){
						#if 0 ////Generate Pin Code randomly
						unsigned int rpin = 0;
						char val[13];
						int val_len;
						
						rpin = wps_generate_pin();
						val_len = os_snprintf(val, sizeof(val), "pin=%08d", rpin);
						#endif
						tls_cmd_get_wps_pin(&tmp_wps);
						//Response to User
						len = sprintf(res_resp, "+OK: ");
						for (i = 0; i < WPS_PIN_LEN; i++) {
							sprintf(res_resp + len + i, "%c", tmp_wps.pin[i]);
						} 
						len += WPS_PIN_LEN;
						*res_len = len;
						 
						return 0; 
//						break;
					}else if(!strcmp(tok->arg[0], "set_pin")){
						// set pin code to system
						if(tok->arg_found != 2){
							err = 1;
							break;
						}
						
						len = tok->arg[2] - tok->arg[1] - 1;
						if (len != 8) {
							err = 1;
							break;
						}
						
						for (i = 0; i<len; i++) {
							wps.pin[i] = (u8)tok->arg[1][i]; 
						}
						wps.pin_len = len;
						
						MEMCPY(tmp_wps.pin, wps.pin, wps.pin_len);
						tls_cmd_set_wps_pin(&tmp_wps, update_flash);

						break; 
					}else if(!strcmp(tok->arg[0], "start_pin")){
						
						
						err = tls_wps_start_pin();
						break;
					}else if(!strcmp(tok->arg[0], "start_pbc")){
						
						err = tls_wps_start_pbc();
						break; 
					}
			} while(0);
	
			if (err) {
				*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
			} else {
				*res_len = atcmd_ok_resp(res_resp);
			}
		} else {
			ret = tls_cmd_get_wps_params(&wps);
			len = sprintf(res_resp, "+OK=%u", wps.mode);
			if (wps.mode == 1) {
				len += sprintf(res_resp + len, ",");
				/*	PIN mode */
				for (i = 0; i < 8; i++) {
					sprintf(res_resp + len + i, "%c", (u8)wps.pin[i]);
				} 
				len += 8;
			}
			*res_len = len;
		}
		return ret;
	}
#endif


#if TLS_CONFIG_WIFI_PERF_TEST
/******************************************************************
* Description:	
As server: TEST UDP & TCP RX
AT+THT=Ss,-i=1
AT+THT=Ss

As client:
UDP TX:  AT+THT=Cc,192.168.1.100, UDP, -b=10K,-t=10,-i=1
			-b=0: full speed test
			K for kilo bps
			M for Mega bps

TCP TX: AT+THT=Cc,192.168.1.100, TCP, -l=1024,-t=10,-i=1
			-l: 1024 block size; prefer to x * 1024, l < 32
			
			
* Argument:	
			
******************************************************************/
void tht_print_param(struct tht_param* tht)
{
	TLS_DBGPRT_INFO("THT Parameters: \n");
	TLS_DBGPRT_INFO("role: %c\n", tht->role);
	TLS_DBGPRT_INFO("server_hostname: %s\n", tht->server_hostname);
	TLS_DBGPRT_INFO("protocol: %d\n", tht->protocol);	
	TLS_DBGPRT_INFO("report_interval: %d\n", tht->report_interval);	
	TLS_DBGPRT_INFO("duration: %d\n", tht->duration);	
	TLS_DBGPRT_INFO("rate: %llu\n", tht->rate);	
	TLS_DBGPRT_INFO("block_size: %d\n", tht->block_size);	

}
int tht_parse_parameter(struct tht_param* tht, struct tls_atcmd_token_t * tok)
{
	char* tmp;
	int len;
	
	switch (*tok->arg[0]){
		case 'S':
		case 's':
			tht->role = 's';
			#if 0
			if(strcmp(tok->arg[1], "TCP") == 0){
				tht->protocol = Ptcp;
			}
			else if(strcmp(tok->arg[1], "UDP") == 0){
				tht->protocol = Pudp;
			}
			else{
				/* return protocol error*/
				return -1;
			}
			
			if((tmp = strchr(tok->arg[2], '=')) != NULL) {
				tht->report_interval = atoi(tmp+1);
			}
			#endif
			if((tmp = strchr(tok->arg[1], '=')) != NULL) {
				tht->report_interval = atoi(tmp+1);
			}

			tht_print_param(tht);
		break;

		case 'C':
		case 'c':
			tht->role = 'c';

			len = tok->arg[2] - tok->arg[1] - 1	;
			MEMCPY(tht->server_hostname, tok->arg[1], len);
			tht->server_hostname[len] = '\0';

			if(strcmp(tok->arg[2], "TCP") == 0){
				tht->protocol = Ptcp;
				
				if((tmp = strchr(tok->arg[3], '=')) != NULL) {
					tht->block_size = atoi(tmp+1);
				}
			}
			else if(strcmp(tok->arg[2], "UDP") == 0){
				tht->protocol = Pudp;

				if((tmp = strchr(tok->arg[3], '=')) != NULL) {
					tmp += 1;
					tht->rate = unit_atof(tmp);
				}
			}
			else{
				/* return protocol error*/
				return -1;
			}

			if((tmp = strchr(tok->arg[4], '=')) != NULL) {
				tht->duration = atoi(tmp+1);
			}

			if((tmp = strchr(tok->arg[5], '=')) != NULL) {
				tht->report_interval = atoi(tmp+1);
			}

			tht_print_param(tht);
		break;

		default:
			/* print help infor */
			return -1;
		break; 
	}

	return 0;
	

}
extern 	OS_EVENT *tht_q;
extern struct tht_param gThtSys;
static int atcmd_tht_proc(struct tls_atcmd_token_t *tok,
	char *res_resp, u32 *res_len)
{
	int ret; 
	struct tht_param* tht = (struct tht_param*)(&gThtSys);

	CreateThroughputTask();
	
	memset(tht, 0, sizeof(struct tht_param));
	/* parse parameter */
	if(tht_parse_parameter(tht, tok) == 0){
		//OSQPost(tht_q,TLS_MSG_WIFI_PERF_TEST_START);
        tls_os_queue_send(tht_q, TLS_MSG_WIFI_PERF_TEST_START, 0);
        
		*res_len = atcmd_ok_resp(res_resp);
	}else{
		*res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
	}
	return 0;
}
#endif

#if TLS_CONFIG_WIFI_PING_TEST
static int ping_parse_param(struct ping_param *para,
                            struct tls_atcmd_token_t *tok)
{
    int ret = -1;
    
    if (tok->arg_found != 4)
        return -1;

    strcpy(para->host, tok->arg[0]);
    para->interval = atoi(tok->arg[1]);
    para->flags = atoi(tok->arg[2]);
    ret = atoi(tok->arg[3]);

    return ret;
}

/* AT+PING=HOST,INTERVAL(ms),T(0|1),START(1)
   AT+PING=HOST,INTERVAL(ms),T(0|1),STOP(0)
*/
static int atcmd_ping_proc(struct tls_atcmd_token_t *tok,
	                      char *res_resp, u32 *res_len)
{
    int ret = -1;
    struct ping_param para;

    ping_test_create_task();
    
    memset(&para, 0, sizeof(para));
    ret = ping_parse_param(&para, tok);
    if (1 == ret)
    {
        ping_test_start(&para);
        *res_len = sprintf(res_resp, "+OK");
    }
    else if(0 == ret)
    {
        ping_test_stop();
        *res_len = sprintf(res_resp, "+OK");
    }
    else
    {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_INV_PARAMS);
    }

    return 0;
}
#endif

static struct tls_atcmd_t  atcmd_tbl[] = {
#if TLS_CONFIG_AT_CMD
    { "Z", 0, atcmd_reset_proc },
    { "E", 0, atcmd_insdisp_proc },
#if TLS_CONFIG_SOCKET_RAW
    { "ENTM", 0, atcmd_entm_proc },
#endif
    { "ENTS", 0, atcmd_ps_proc },
    { "RSTF", 0, atcmd_reset_flash_proc },
    { "PMTF", 0, atcmd_pmtf_proc },
    { "IOC", 0, atcmd_gpio_proc },
    { "WJOIN", 0, atcmd_wjoin_proc },
    { "WLEAV", 0, atcmd_wleave_proc },
    { "WSCAN", 0, atcmd_wscan_proc },
    { "LKSTT", 0, atcmd_link_status_proc },
#if TLS_CONFIG_AP
    { "SLIST", 0, atcmd_get_sta_info },
#endif
#if TLS_CONFIG_SOCKET_RAW
    { "SKCT", 0, atcmd_skct_proc },
    { "SKSTT", 0, atcmd_skstt_proc },
    { "SKCLS", 0, atcmd_skclose_proc },
    { "SKSDF", 0, atcmd_sksdf_proc },
    { "SKSND", 0, atcmd_sksnd_proc },
    { "SKRCV", 0, atcmd_skrcv_proc },
	{ "SKRPTM", 0, atcmd_sktrptmode_proc },
	{ "SKSRCIP",  0, atcmd_sktsrceip_proc },
	{ "SKGHBN", 0, atcmd_skghbn_proc },
#endif //TLS_CONFIG_SOCKET_RAW
    { "WPRT", 0, atcmd_wprt_proc },
    { "SSID", 0, atcmd_ssid_proc },
    { "KEY", 0, atcmd_key_proc },
#if TLS_CONFIG_APSTA
    { "SSID2", 0, atcmd_ssid2_proc },
    { "QMAC2", 0, atcmd_mac2_proc },
    { "LKSTT2", 0, atcmd_link2_status_proc },
#endif
    { "ENCRY", 0, atcmd_encrypt_proc },
    { "BSSID", 0, atcmd_bssid_proc },
    { "BRDSSID", 0, atcmd_brd_ssid_proc },
    { "CNTPARAM", 0, atcmd_get_connect_param_proc },
    { "CHL", 0, atcmd_chnl_proc },
    { "CHLL", 0, atcmd_chll_proc },
    { "WREG", 0, atcmd_wreg_proc },
    { "WBGR", 0, atcmd_wbgr_proc },
    { "WATC", 0, atcmd_watc_proc },
    { "WPSM", 0, atcmd_wpsm_proc },
    { "WARC", 0, atcmd_warc_proc },
    { "WARM", 0, atcmd_warm_proc },
    { "NIP", 0, atcmd_nip_proc },
    { "ATM", 0, atcmd_atm_proc },
    { "ATRM", 0, atcmd_atrm_proc },
    { "AOLM", 0, atcmd_aolm_proc },
    { "PORTM", 0, atcmd_portm_proc },
    { "UART", 0, atcmd_uart_proc },
    { "ATLT", 0, atcmd_atlt_proc },
    { "DNS", 0, atcmd_dns_proc },
    { "DDNS", 0, atcmd_ddns_proc },
    { "UPNP", 0, atcmd_upnp_proc },
    { "DNAME", 0, atcmd_dname_proc },
    { "ATPT", 0, atcmd_atpt_proc },
    { "&DBG", 0, atcmd_dbg_proc },
	{ "ESPC",  0, atcmd_espc_proc },
	{ "ESPT",  0, atcmd_espt_proc },
	{ "WEBS",  0, atcmd_webs_proc },
	{ "IOM",   0, atcmd_iom_proc },
	{ "CMDM",  0, atcmd_cmdm_proc },
	{ "PASS",  0, atcmd_pass_proc },	
	{ "ONESHOT", 0, atcmd_set_oneshot_proc },
    { "&UPDP", 0, atcmd_updp_proc },   
#if TLS_CONFIG_HTTP_CLIENT_TASK
    { "HTTPC", 0, atcmd_http_client_proc },   
#endif
#endif
    { "QMAC", 0, atcmd_mac_proc },
    { "QVER", 0, atcmd_ver_proc },
	{ "&UPDM", 0, atcmd_updm_proc },
	{ "&UPDD", 0, atcmd_updd_proc },  
    { "&REGR", 0, atcmd_regr_proc },
    { "&REGW", 0, atcmd_regw_proc },
    { "&RFR", 0, atcmd_rfr_proc },
    { "&RFW", 0, atcmd_rfw_proc },
    { "&FLSR", 0, atcmd_flsr_proc },
    { "&FLSW", 0, atcmd_flsw_proc },
	{ "&TXG", 0, atcmd_txg_proc },
	{ "&MAC", 0, atcmd_mac_proc },
	{ "&HWV", 0, atcmd_hwv_proc },
	{ "&SPIF", 0, atcmd_spif_proc },
	{ "&LPCHL", 0, atcmd_lpchl_proc },
	{ "&LPTSTR", 0, atcmd_lptstr_proc },
	{ "&LPTSTP", 0, atcmd_lptstp_proc },
	{ "&LPTSTT", 0, atcmd_lptstt_proc },
	{ "&LPRSTR", 0, atcmd_lprstr_proc },
	{ "&LPRSTP", 0, atcmd_lprstp_proc },
	{ "&LPRSTT", 0, atcmd_lprstt_proc },
	{ "&LPPSTR", 0, atcmd_lppstr_proc },
	{ "&LPPSTP", 0, atcmd_lppstp_proc },
	{ "&LPRFPS", 0, atcmd_lprfps_proc },
	{ "&LPCHRS", 0, atcmd_lpchrs_proc },
	{ "&LPTBD", 0, atcmd_lptbd_proc },
	{ "&LPSTPT", 0, atcmd_lpstpt_proc },
	{ "&LPCHLR", 0, atcmd_lpchlr_proc },
	{ "&LPSTPR", 0, atcmd_lpstpr_proc },
	{ "&LPRAGC", 0, atcmd_lpragc_proc },
	{ "&LPRSR", 0, atcmd_lprsr_proc },
	{ "&RWHWV", 0, atcmd_rwhwv_proc },

#if TLS_CONFIG_WIFI_PERF_TEST
	{ "THT", 0, atcmd_tht_proc},
#endif
#if TLS_CONFIG_WIFI_PING_TEST
	{ "PING", 0, atcmd_ping_proc},
#endif
#if TLS_CONFIG_WPS    
    { "WWPS", 0, atcmd_wps_proc },
#endif
	{ "CUSTDATA", 0, atcmd_custdata_proc},
    { NULL, 0, NULL },
};

int atcmd_err_resp(char *buf, int err_code)
{
    int len;
    len = sprintf(buf, "+ERR=%d", -err_code);
    return len;
}

int atcmd_ok_resp(char *buf)
{
    int len;
    len = sprintf(buf, "+OK");
    return len;
}


static int atcmd_nop_proc(struct tls_atcmd_token_t *tok, 
        char *res_resp, u32 *res_len)
{
    if (!tok->arg_found && (tok->op == ATCMD_OP_NULL)) {
        *res_len = atcmd_ok_resp(res_resp);
    } else {
        *res_len = atcmd_err_resp(res_resp, CMD_ERR_OPS);
    }

    return 0; 
}
int tls_atcmd_parse(struct tls_atcmd_token_t *tok, char *buf, u32 len)
{
    char *c, *end_line, *comma;
    int remain_len;
    char *buf_start = buf;
    int ssid_len;

    /* at command "AT+", NULL OP */
    if (len == 0) {
        *tok->name = '\0';
        tok->arg_found = 0;
        return -1;
    }

    /* at command "+SSID" must process specially, 
     * because ssid include ASCII ',', or '?'  */
    if ((buf[0] == 'S' || buf[0] == 's') &&
        (buf[1] == 'S' || buf[1] == 's') &&
        (buf[2] == 'I' || buf[2] == 'i') &&
        (buf[3] == 'D' || buf[3] == 'd'))
    {
        if ('2' == buf[4])
        {
            MEMCPY(tok->name, buf, 5); 
            buf += 5;
        }
        else
        {
            MEMCPY(tok->name, buf, 4); 
            buf += 4;
        }
        
        if (*buf != '=') {
            if (*buf == '\n') {
                *buf = '\0';
                tok->op = ATCMD_OP_NULL;
                tok->arg_found = 0;
                return 0;
            } else {
                return -CMD_ERR_INV_PARAMS;
            }
        }
        buf++;
        switch(*buf) {
            case '!':
                tok->op = ATCMD_OP_EP;
                buf++;
                break;
            case '?':
                tok->op = ATCMD_OP_QU;
                buf++;
                break;
            default:
                tok->op = ATCMD_OP_EQ;
                break;
        }
        tok->arg[0] = buf;
        c = strchr(buf, '\n');
        ssid_len = c - buf;
        if (ssid_len > 34) {
            return -CMD_ERR_INV_PARAMS;
        } else {
            if ((ssid_len == 0) && (tok->op == ATCMD_OP_QU)) {
                tok->arg_found = 0;
            } else if ((tok->op == ATCMD_OP_QU) && (ssid_len != 0)){
                return -CMD_ERR_INV_PARAMS;
            } else {
                tok->arg_found = 1;
                tok->arg[1] = c + 1; 
            }
            return 0;
        }
    }

    /* parse command name */
    c = strchr(buf, '=');
    if (!c) {
        /* format :  at+wprt */
        c = strchr(buf, '\n');
        if (!c)
            return -CMD_ERR_INV_FMT;
        if ((c - buf) > (ATCMD_NAME_MAX_LEN - 1)) 
            return -CMD_ERR_UNSUPP;
        MEMCPY(tok->name, buf, c-buf);
        *(tok->name + (c-buf)) = '\0';
        tok->op = ATCMD_OP_NULL;
        tok->arg_found = 0;
        return 0;
    } else {
        /* format : at+wprt=0 
         *          at+skct=0,0,192.168.1.4,80 */
        if ((c - buf) > (ATCMD_NAME_MAX_LEN - 1)) 
            return -CMD_ERR_UNSUPP;
        MEMCPY(tok->name, buf, c-buf);
        *(tok->name + (c-buf)) = '\0';
        tok->op = ATCMD_OP_NULL;
        buf += (c-buf + 1);
        switch(*buf) {
            case '!':
                tok->op = ATCMD_OP_EP;
                buf++;
                break;
            case '?':
                tok->op = ATCMD_OP_QU;
                buf++;
                break;
            default:
                tok->op = ATCMD_OP_EQ;
                break;
        }
        tok->arg[0] = buf;
        tok->arg_found = 0;
        remain_len = len - (buf - buf_start);
        end_line = strchr(buf, '\n');
        if (!end_line)
            return -CMD_ERR_INV_FMT;
        while (remain_len > 0) {
            comma = strchr(buf, ',');
            if (end_line && !comma) {
                if (tok->arg_found >= (ATCMD_MAX_ARG - 1))
                    return -CMD_ERR_INV_PARAMS;
                if (end_line != buf)
                    tok->arg_found++;
                /* last parameter */
                *(u8 *)end_line = '\0';
                tok->arg[tok->arg_found] = end_line + 1;
                remain_len -= (end_line - buf);
                if (remain_len > 1)
                    return -CMD_ERR_NOT_ALLOW;
                else 
                    return 0;
            } else {
                if (tok->arg_found >= (ATCMD_MAX_ARG - 1)) 
                    return -CMD_ERR_INV_PARAMS;
                tok->arg_found++;
                *(u8 *)comma = '\0';
                tok->arg[tok->arg_found] = comma + 1;
                remain_len -= (comma - buf + 1);
                buf = comma + 1;
            }
        } 
        return 0;
    } 
}

int tls_atcmd_exec(
        struct tls_atcmd_token_t *tok,
        char *res_rsp, u32 *res_len)
{
    int err;
	struct tls_atcmd_t *atcmd, *match = NULL;

    if (strlen(tok->name) == 0) {
        err = atcmd_nop_proc(tok, res_rsp, res_len);
        return err;
    }

    /* look for AT CMD handle table */
	atcmd = atcmd_tbl;
	while (atcmd->name) {
		if (strcmp(atcmd->name, tok->name) == 0) {
			match = atcmd;
            break;
		}
		atcmd++;
	}
	TLS_DBGPRT_INFO("ATCMD:%s\t match:0x%x\n", tok->name, match);

    /* at command handle */
    if (match) {
        //TLS_DBGPRT_INFO("command find: %s\n", atcmd->name);
        err = match->proc_func(tok, res_rsp, res_len); 
    } else {
        /* at command not found */
        *res_len = sprintf(res_rsp, "+ERR=-2"); 
        err = -CMD_ERR_UNSUPP;
    }

    return err;
}
#endif

