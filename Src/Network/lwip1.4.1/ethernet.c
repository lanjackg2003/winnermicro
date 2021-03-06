


/* lwIP includes */
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"
#include "netif/ethernetif.h"
#include "ethernet.h"
#include "wm_params.h"
#include "wm_mem.h"
#include <string.h>
#if TLS_CONFIG_AP
#include "dhcp_server.h"
#include "dns_server.h"
#endif
#if TLS_CONFIG_SOCKET_RAW
#include "tls_netconn.h"
#endif
#if TLS_CONFIG_APSTA
#include "lwip/alg.h"
#include "tls_wireless.h"
#endif
extern int tls_wifi_get_oneshot_flag(void);

struct tls_ethif *ethif = NULL;
struct netif *nif = NULL;
struct tls_netif_status_event netif_status_event;
static void netif_status_changed(struct netif *netif)
{
    struct tls_netif_status_event *status_event;
    ethif->status = netif_is_up(nif);
#if TLS_CONFIG_APSTA
    u8 mode;
    tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void* )&mode, FALSE);
#endif
    dl_list_for_each(status_event, &netif_status_event.list, struct tls_netif_status_event, list)
    {
        if(status_event->status_callback != NULL && netif_is_up(netif))
        {
        	if (0 == tls_wifi_get_oneshot_flag())
			{
#if TLS_CONFIG_APSTA
	            if (IEEE80211_MODE_APSTA == mode)
	            {
	                if (netif_is_up(nif) && !netif_is_up(nif->next))
	                    status_event->status_callback(NETIF_APSTA_STA_NET_UP);
	                else if (netif_is_up(nif) && netif_is_up(nif->next))
	                    status_event->status_callback(NETIF_IP_NET_UP);
	            }
	            else
#endif
	            {
	                status_event->status_callback(NETIF_IP_NET_UP);
	            }
        	}
        }
    }
}

static void wifi_status_changed(u8 status)
{
    struct tls_netif_status_event *status_event;
    dl_list_for_each(status_event, &netif_status_event.list, struct tls_netif_status_event, list)
    {
        if(status_event->status_callback != NULL)
        {
            switch(status)
            {
                case WIFI_JOIN_SUCCESS:
                    status_event->status_callback(NETIF_WIFI_JOIN_SUCCESS);
                    break;
                case WIFI_JOIN_FAILED:
                    status_event->status_callback(NETIF_WIFI_JOIN_FAILED);
                    break;
                case WIFI_DISCONNECTED:
                    status_event->status_callback(NETIF_WIFI_DISCONNECTED);
                    break;
#if TLS_CONFIG_APSTA
                case WIFI_APSTA_STA_JOIN_SUCCESS:
                    status_event->status_callback(NETIF_WIFI_APSTA_STA_SUCCESS);
                    break;
                case WIFI_APSTA_AP_JOIN_SUCCESS:
                    status_event->status_callback(NETIF_WIFI_APSTA_AP_SUCCESS);
                    break;
#endif
                default:
                    break;
            }
        }
    }
}
/*************************************************************************** 
* Function: Tcpip_stack_init
*
* Description: This function is init ip stack. 
* 
* Input: 
*		ipaddr:  
*		netmask: 
*       gateway: 
* Output: 
* 
* Return: 
*		netif: Init IP Stack OK
*       NULL : Init IP Statck Fail Because no memory
* Date : 2014-6-4 
****************************************************************************/ 
struct netif *Tcpip_stack_init()
{
#if TLS_CONFIG_APSTA
    struct netif *nif4apsta = NULL;
#endif

	/*Register Ethernet Rx Data callback From wifi*/
	tls_ethernet_data_rx_callback(ethernetif_input);
#if TLS_CONFIG_APSTA
	tls_ethernet_ip_rx_callback(alg_input);
#endif
	
    /* Setup lwIP. */
    tcpip_init(NULL, NULL);

#if TLS_CONFIG_APSTA
    /* add net info for apsta's ap */
    nif4apsta = (struct netif *)tls_mem_alloc(sizeof(struct netif));
    if (nif4apsta == NULL)
        return NULL;
#endif

    /*Add Net Info to Netif, default */
    nif = (struct netif *)tls_mem_alloc(sizeof(struct netif));
    if (nif == NULL)
    {
#if TLS_CONFIG_APSTA
        tls_mem_free(nif4apsta);
#endif
        return NULL;
    }

#if TLS_CONFIG_APSTA
    memset(nif4apsta, 0, sizeof(struct netif));
    nif->next = nif4apsta;
    netifapi_netif_add(nif4apsta, IPADDR_ANY, IPADDR_ANY, IPADDR_ANY, NULL, ethernetif_init, tcpip_input);
    netif_set_status_callback(nif4apsta, netif_status_changed);
#endif

    memset(nif, 0, sizeof(struct netif));
    netifapi_netif_add(nif, IPADDR_ANY,IPADDR_ANY,IPADDR_ANY,NULL,ethernetif_init,tcpip_input);
    netifapi_netif_set_default(nif);
    dl_list_init(&netif_status_event.list);
    netif_set_status_callback(nif, netif_status_changed);
    tls_wifi_status_change_cb_register(wifi_status_changed);
    return nif;
}

#ifndef TCPIP_STACK_INIT
#define TCPIP_STACK_INIT Tcpip_stack_init
#endif
int tls_ethernet_init()
{
    if(ethif)
        tls_mem_free(ethif);
    ethif = tls_mem_alloc(sizeof(struct tls_ethif));
    memset(ethif, 0, sizeof(struct tls_ethif));

    TCPIP_STACK_INIT();
#if TLS_CONFIG_SOCKET_RAW
    tls_net_init();
#endif
    return 0;
}

struct tls_ethif * tls_netif_get_ethif(void)
{
    ip_addr_t dns1,dns2;
    MEMCPY((char *)&ethif->ip_addr.addr, &nif->ip_addr.addr, 4);
    MEMCPY((char *)&ethif->netmask.addr, &nif->netmask.addr, 4);
    MEMCPY((char *)&ethif->gw.addr, &nif->gw.addr, 4);
    dns1 = dns_getserver(0);
    MEMCPY(&ethif->dns1.addr, (char *)&dns1.addr, 4);
    dns2 = dns_getserver(1);
    MEMCPY(&ethif->dns2.addr, (char *)&dns2.addr, 4);
	ethif->status = nif->flags&NETIF_FLAG_UP;
    return ethif;
}

err_t tls_dhcp_start(void)
{
	
	if (nif->flags & NETIF_FLAG_UP) 
	  nif->flags &= ~NETIF_FLAG_UP;
	
    return netifapi_dhcp_start(nif);
}

err_t tls_dhcp_stop(void)
{
    return netifapi_dhcp_stop(nif);
}

err_t tls_netif_set_addr(ip_addr_t *ipaddr,
                        ip_addr_t *netmask,
                        ip_addr_t *gw)
{
    return netifapi_netif_set_addr(nif, ipaddr, netmask, gw);
}
void tls_netif_dns_setserver(u8 numdns, ip_addr_t *dnsserver)
{
    dns_setserver(numdns, dnsserver);
}
err_t tls_netif_set_up(void)
{
    return netifapi_netif_set_up(nif);
}
err_t tls_netif_set_down(void)
{
    return netifapi_netif_set_down(nif);
}
err_t tls_netif_add_status_event(tls_netif_status_event_fn event_fn)
{
    u32 cpu_sr;
    struct tls_netif_status_event *evt;
    //if exist, remove from event list first.
    tls_netif_remove_status_event(event_fn);
    evt = tls_mem_alloc(sizeof(struct tls_netif_status_event));
    if(evt==NULL)
        return -1;
    memset(evt, 0, sizeof(struct tls_netif_status_event));
    evt->status_callback = event_fn;
    cpu_sr = tls_os_set_critical();
    dl_list_add_tail(&netif_status_event.list, &evt->list);
    tls_os_release_critical(cpu_sr);

	return 0;
}
err_t tls_netif_remove_status_event(tls_netif_status_event_fn event_fn)
{
    struct tls_netif_status_event *status_event;
    bool is_exist = FALSE;
    u32 cpu_sr;
    if(dl_list_empty(&netif_status_event.list))
        return 0;
    dl_list_for_each(status_event, &netif_status_event.list, struct tls_netif_status_event, list)
    {
        if(status_event->status_callback == event_fn)
        {
            is_exist = TRUE;
            break;
        }
    }
    if(is_exist)
    {
        cpu_sr = tls_os_set_critical();
        dl_list_del(&status_event->list);
        tls_os_release_critical(cpu_sr);
        tls_mem_free(status_event);
    }
		return 0;
}

	
#if TLS_CONFIG_AP
INT8S tls_dhcps_start(void)
{
#if TLS_CONFIG_APSTA
    u8 mode;
    tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void* )&mode, FALSE);
    if (IEEE80211_MODE_APSTA == mode)
        return DHCPS_Start(nif->next);
    else
#endif
        return DHCPS_Start(nif);
}
void tls_dhcps_stop(void)
{
    DHCPS_Stop();
}

INT8S tls_dnss_start(INT8U * DnsName)
{
    return DNSS_Start(nif, DnsName);
}
void tls_dnss_stop(void)
{
    DNSS_Stop();
}
struct ip_addr *tls_dhcps_getip(const u8_t *mac)
{
	return DHCPS_GetIpByMac(mac);
}
#endif

#if TLS_CONFIG_APSTA
err_t tls_netif2_set_up(void)
{
    return netifapi_netif_set_up(nif->next);
}
err_t tls_netif2_set_down(void)
{
    return netifapi_netif_set_down(nif->next);
}
err_t tls_netif2_set_addr(ip_addr_t *ipaddr,
                          ip_addr_t *netmask,
                          ip_addr_t *gw)
{
    return netifapi_netif_set_addr(nif->next, ipaddr, netmask, gw);
}
/* numdns 0/1  --> dns 1/2 */
void tls_dhcps_setdns(u8_t numdns)
{
    ip_addr_t dns;
	dns = dns_getserver(numdns);
	DHCPS_SetDns(numdns, dns.addr);

	return;
}
#endif

struct netif *tls_get_netif(void)
{
    return nif;
}

