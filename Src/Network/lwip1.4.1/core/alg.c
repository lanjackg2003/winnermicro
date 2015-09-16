/******************************************************************************

  Copyright (C) 2015 Winner Micro electronics Co., Ltd.

 ******************************************************************************
  File Name     : alg.c
  Version       : Initial Draft
  Author        : Li Limin, lilm@winnermicro.com
  Created       : 2015/3/7
  Last Modified :
  Description   : Application layer gateway, (alg) only for apsta

  History       :
  1.Date        : 2015/3/7
    Author      : Li Limin, lilm@winnermicro.com
    Modification: Created file

******************************************************************************/
#include <stdio.h>
#include <string.h>
#include "tls_common.h"
#include "ip.h"
#include "udp.h"
#include "icmp.h"
#include "tcp_impl.h"
#include "lwip/sys.h"
#include "lwip/alg.h"
#include "netif/ethernetif.h"

#if TLS_CONFIG_APSTA
extern u8 *wpa_supplicant_get_mac2(void);
extern struct netif *tls_get_netif(void);

/* ��ӡnapt����ͳ����Ϣ */
//#define NAPT_ALLOC_DEBUG
#ifdef  NAPT_ALLOC_DEBUG
static u16 napt4ic_cnt;
static u16 napt4tcp_cnt;
static u16 napt4udp_cnt;
#endif

/* ��̫������ͷ�̶���С, 14�ֽ� */
#define NAPT_ETH_HDR_LEN             sizeof(struct ethhdr)

/* У���16bit����, 2�ֽ� */
#define NAPT_CHKSUM_16BIT_LEN        sizeof(u16)

/* �������������� */
#define NAPT_TABLE_FOREACH(pos, head)\
         for (pos = head.next; NULL != pos; pos = pos->next)

/* napt tcp/udp ����ṹ */
struct napt_addr_4tu{
    struct napt_addr_4tu *next;
    u16 src_port;
    u16 new_port;
    u8 src_ip;
    u8 time_stamp;
};

/* napt icmp ����ṹ */
struct napt_addr_4ic{
    struct napt_addr_4ic *next;
    u16 src_id;/* icmp id */
    u8 src_ip;
    u8 time_stamp;
};

struct napt_table_head_4tu{
    struct napt_addr_4tu *next;
#ifdef NAPT_TABLE_LIMIT
    u16 cnt;
#endif
};

struct napt_table_head_4ic{
    struct napt_addr_4ic *next;
#ifdef NAPT_TABLE_LIMIT
    u16 cnt;
#endif
};

/* napt��������ͷ */
static struct napt_table_head_4tu napt_table_4tcp;
static struct napt_table_head_4tu napt_table_4udp;
static struct napt_table_head_4ic napt_table_4ic;

/* napt�������������������̶���lwipһ������������ﴦ������������� */
//#define NAPT_TABLE_MUTEX_LOCK
#ifdef  NAPT_TABLE_MUTEX_LOCK
static sys_mutex_t napt_table_lock_4tcp;
static sys_mutex_t napt_table_lock_4udp;
static sys_mutex_t napt_table_lock_4ic;
#endif

/* �˿ڳ��α� */
static u16 napt_curr_port;

/*****************************************************************************
 Prototype    : alg_napt_mem_alloc
 Description  : ����һ�������ڴ�
 Input        : u32 size        ��������ڴ��С
 Output       : None
 Return Value : void*    NULL   ����ʧ��
                        !NULL   ����ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline void *alg_napt_mem_alloc(u32 size)
{
    return mem_malloc(size);
}

/*****************************************************************************
 Prototype    : alg_napt_mem_free
 Description  : �ͷ�һ�������ڴ�
 Input        : void *p        ���ͷŵ��ڴ�
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline void alg_napt_mem_free(void *p)
{
    mem_free(p);
    return;
}

#ifdef NAPT_TABLE_LIMIT
/*****************************************************************************
 Prototype    : alg_napt_table_is_full
 Description  : ���napt�����Ƿ��Ѵ����ֵ
 Input        : void  
 Output       : None
 Return Value : bool    true   ��������
                        false  ����δ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline bool alg_napt_table_is_full(void)
{
    bool is_full = false;

    if ((napt_table_4tcp.cnt + napt_table_4udp.cnt + napt_table_4ic.cnt) >= NAPT_TABLE_SIZE_MAX)
    {
#ifdef NAPT_ALLOC_DEBUG 
        printf("@@@ napt batle: limit is reached for tcp/udp.\r\n");
#endif
        LWIP_DEBUGF(NAPT_DEBUG, ("napt batle: limit is reached for tcp/udp.\n"));
        is_full = true;
    }

    return is_full;
}
#endif

/*****************************************************************************
 Prototype    : alg_napt_port_alloc
 Description  : ����һ��napt�˿ں�
 Input        : void  
 Output       : None
 Return Value : u16    0      ʧ��
                       other  �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline u16 alg_napt_port_alloc(void)
{
    u8_t i;
    u16 cnt = 0;
    struct udp_pcb *udp_pcb;
    struct tcp_pcb *tcp_pcb;
    struct napt_addr_4tu *napt_tcp;
    struct napt_addr_4tu *napt_udp;

again:
    if (napt_curr_port++ == NAPT_LOCAL_PORT_RANGE_END)
    {
        napt_curr_port = NAPT_LOCAL_PORT_RANGE_START;
    }

    /* udp */
    for(udp_pcb = udp_pcbs; udp_pcb != NULL; udp_pcb = udp_pcb->next)
    {
        if (udp_pcb->local_port == napt_curr_port)
        {
            if (++cnt > (NAPT_LOCAL_PORT_RANGE_END - NAPT_LOCAL_PORT_RANGE_START))
            {
                return 0;
            }
            goto again;
        }
    }    

    /* tcp */
    for (i = 0; i < NUM_TCP_PCB_LISTS; i++)
    {
        for(tcp_pcb = *tcp_pcb_lists[i]; tcp_pcb != NULL; tcp_pcb = tcp_pcb->next)
        {
            if (tcp_pcb->local_port == napt_curr_port)
            {
                if (++cnt > (NAPT_LOCAL_PORT_RANGE_END - NAPT_LOCAL_PORT_RANGE_START))
                {
                    return 0;
                }
                goto again;
            }
        }
    }

    /* tcp napt */
    NAPT_TABLE_FOREACH(napt_tcp, napt_table_4tcp)
    {
        if (napt_tcp->new_port == napt_curr_port)
        {
            if (++cnt > (NAPT_LOCAL_PORT_RANGE_END - NAPT_LOCAL_PORT_RANGE_START))
            {
                return 0;
            }
            goto again;
        }
    }

    /* udp napt */
    NAPT_TABLE_FOREACH(napt_udp, napt_table_4udp)
    {
        if (napt_udp->new_port == napt_curr_port)
        {
            if (++cnt > (NAPT_LOCAL_PORT_RANGE_END - NAPT_LOCAL_PORT_RANGE_START))
            {
                return 0;
            }
            goto again;
        }
    }

    return napt_curr_port;
}

/*****************************************************************************
 Prototype    : alg_napt_get_by_id
 Description  : ͨ��icmp echo id����napt����
 Input        : u16 id          icmp echo id
 Output       : None
 Return Value : struct napt_addr_4ic *      NULL   ʧ��
                                           !NULL   �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4ic *alg_napt_get_by_id(u16 id)
{
    struct napt_addr_4ic *ret = NULL;
    struct napt_addr_4ic *napt;

    NAPT_TABLE_FOREACH(napt, napt_table_4ic)
    {
        if (id == napt->src_id)
        {
	       ret = napt;
	       break;
        }
    }

    return ret;
}

/*****************************************************************************
 Prototype    : alg_napt_table_insert_4ic
 Description  : ����napt����
 Input        : u16 id          Դid
                u8  ip          Դip��ַ
 Output       : None
 Return Value : struct napt_addr_4ic *      NULL   ʧ��
                                           !NULL   �ɹ�
 Note         : icmp���Ľ��٣��ݲ�����������
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4ic *alg_napt_table_insert_4ic(u16 id, u8 ip)
{
    struct napt_addr_4ic *napt;

#ifdef NAPT_TABLE_LIMIT
    if (true == alg_napt_table_is_full())
    {
        return NULL;
    }
#endif

    napt = alg_napt_mem_alloc(sizeof(struct napt_addr_4ic));
    if (NULL == napt)
    {
        return NULL;
    }

    memset(napt, 0, sizeof(struct napt_addr_4ic));
    napt->src_id = id;
    napt->src_ip = ip;
    napt->time_stamp++;

#ifdef NAPT_TABLE_LIMIT
    napt_table_4ic.cnt++;
#endif
    napt->next = napt_table_4ic.next;
    napt_table_4ic.next = napt;
    
#ifdef NAPT_ALLOC_DEBUG 
    printf("@@ napt id alloc %hu\r\n", ++napt4ic_cnt);
#endif

    return napt;
}

/*****************************************************************************
 Prototype    : alg_napt_table_update_4ic
 Description  : ˢ��napt����ʱ���
 Input        : struct napt_addr_4ic *napt  
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline void alg_napt_table_update_4ic(struct napt_addr_4ic *napt)
{
    if (!++napt->time_stamp)
        napt->time_stamp++;

    return;
}

/*****************************************************************************
 Prototype    : alg_napt_get_tcp_port_by_dest
 Description  : ����Ŀ�Ķ˿ںŲ���napt����
 Input        : u16 port    Ŀ�Ķ˿ں�
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   ʧ��
                                       !NULL   �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4tu *alg_napt_get_tcp_port_by_dest(u16 port)
{
    struct napt_addr_4tu *ret = NULL;
    struct napt_addr_4tu *napt;

    NAPT_TABLE_FOREACH(napt, napt_table_4tcp)
    {
        if (napt->new_port == port)
        {
            ret = napt;
            break;
        }
    }

    return ret;
}

/*****************************************************************************
 Prototype    : alg_napt_get_tcp_port_by_src
 Description  : ����Դ�˿ںź�Դip��ַ����napt����
 Input        : u16 port    Դ�˿ں�
                u8  ip      Դip��ַ
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   ʧ��
                                       !NULL   �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4tu *alg_napt_get_tcp_port_by_src(u16 port, u8 ip)
{
    struct napt_addr_4tu *ret = NULL;
    struct napt_addr_4tu *napt;

    NAPT_TABLE_FOREACH(napt, napt_table_4tcp)
    {
        if (port == napt->src_port)
        {
            if (ip == napt->src_ip)
            {
                ret = napt;
                break;
            }
        }
    }

    return ret;
}

/*****************************************************************************
 Prototype    : alg_napt_table_insert_4tcp
 Description  : ����napt����
 Input        : u16 src_port    Դ�˿ں�
                u8  ip          Դip��ַ
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   ʧ��
                                            !NULL   �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4tu *alg_napt_table_insert_4tcp(u16 src_port, u8 ip)
{
    u16 new_port;
    struct napt_addr_4tu *napt;

#ifdef NAPT_TABLE_LIMIT
    if (true == alg_napt_table_is_full())
    {
        return NULL;
    }
#endif

    new_port = alg_napt_port_alloc();
    if (0 == new_port)
    {
        return NULL;
    }

    napt = alg_napt_mem_alloc(sizeof(struct napt_addr_4tu));
    if (NULL == napt)
    {
        return NULL;
    }

    memset(napt, 0, sizeof(struct napt_addr_4tu));
    napt->src_port = src_port;
    napt->new_port = htons(new_port);
    napt->src_ip = ip;
    napt->time_stamp++;

#ifdef NAPT_TABLE_LIMIT
    napt_table_4tcp.cnt++;
#endif
    napt->next = napt_table_4tcp.next;
    napt_table_4tcp.next = napt;

#ifdef NAPT_ALLOC_DEBUG 
    printf("@@ napt tcp port alloc %hu\r\n", ++napt4tcp_cnt);
#endif

    return napt;
}

/*****************************************************************************
 Prototype    : alg_napt_table_update_4tcp
 Description  : ˢ��napt����ʱ���
 Input        : struct napt_addr_4tu *napt  
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline void alg_napt_table_update_4tcp(struct napt_addr_4tu *napt)
{
    if (!++napt->time_stamp)
        napt->time_stamp++;

    return;
}

/*****************************************************************************
 Prototype    : alg_napt_get_udp_port_by_dest
 Description  : ����Ŀ�Ķ˿ںŲ���napt����
 Input        : u16 port    Ŀ�Ķ˿ں�
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   ʧ��
                                            !NULL   �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4tu *alg_napt_get_udp_port_by_dest(u16 port)
{
    struct napt_addr_4tu *ret = NULL;
    struct napt_addr_4tu *napt;

    NAPT_TABLE_FOREACH(napt, napt_table_4udp)
    {
        if (napt->new_port == port)
        {
            ret = napt;
            break;
        }
    }

    return ret;
}

/*****************************************************************************
 Prototype    : alg_napt_get_udp_port_by_src
 Description  : ����Դ�˿ںź�Դip��ַ����napt����
 Input        : u16 port    Դ�˿ں�
                u8  ip      Դip��ַ
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   ʧ��
                                            !NULL   �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4tu *alg_napt_get_udp_port_by_src(u16 port, u8 ip)
{
    struct napt_addr_4tu *ret = NULL;
    struct napt_addr_4tu *napt;

    NAPT_TABLE_FOREACH(napt, napt_table_4udp)
    {
        if (port == napt->src_port)
        {
            if (ip == napt->src_ip)
            {
                ret = napt;
                break;
            }
        }
    }

    return ret;
}

/*****************************************************************************
 Prototype    : alg_napt_table_insert_4udp
 Description  : ����napt����
 Input        : u16 src_port    Դ�˿ں�
                u8  ip          Դip��ַ
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   ʧ��
                                            !NULL   �ɹ�
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline struct napt_addr_4tu *alg_napt_table_insert_4udp(u16 src_port, u8 ip)
{
    u16 new_port;
    struct napt_addr_4tu *napt;

#ifdef NAPT_TABLE_LIMIT
    if (true == alg_napt_table_is_full())
    {
        return NULL;
    }
#endif

    new_port = alg_napt_port_alloc();
    if (0 == new_port)
    {
        return NULL;
    }

    napt = alg_napt_mem_alloc(sizeof(struct napt_addr_4tu));
    if (NULL == napt)
    {
        return NULL;
    }

    memset(napt, 0, sizeof(struct napt_addr_4tu));
    napt->src_port = src_port;
    napt->new_port = htons(new_port);
    napt->src_ip = ip;
    napt->time_stamp++;

#ifdef NAPT_TABLE_LIMIT
    napt_table_4udp.cnt++;
#endif
    napt->next = napt_table_4udp.next;
    napt_table_4udp.next = napt;

#ifdef NAPT_ALLOC_DEBUG 
    printf("@@ napt udp port alloc %hu\r\n", ++napt4udp_cnt);
#endif

    return napt;
}

/*****************************************************************************
 Prototype    : alg_napt_table_update_4udp
 Description  : ˢ��napt����ʱ���
 Input        : struct napt_addr_4tu *napt  
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline void alg_napt_table_update_4udp(struct napt_addr_4tu *napt)
{
    if (!++napt->time_stamp)
        napt->time_stamp++;

    return;
}

/*****************************************************************************
 Prototype    : alg_napt_table_check_4ic
 Description  : icmp napt�����ϻ�������
 Input        : void  
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static void alg_napt_table_check_4ic(void)
{
    struct napt_addr_4ic *napt4ic;
    struct napt_addr_4ic *napt4ic_prev;

    /* icmp */
#ifdef NAPT_TABLE_MUTEX_LOCK
    sys_mutex_lock(napt_table_lock_4ic);
#endif
    /* ���ֱ�����ʽ��©����һ����¼ */
    for (napt4ic_prev = napt_table_4ic.next;\
         NULL != napt4ic_prev;\
         napt4ic_prev = napt4ic_prev->next)
    {
        napt4ic = napt4ic_prev->next;
        if (NULL != napt4ic)
        {
            if (0 == napt4ic->time_stamp)
            {
#ifdef NAPT_TABLE_LIMIT
                napt_table_4ic.cnt--;
#endif
                napt4ic_prev->next = napt4ic->next;
                napt4ic->next = NULL;
                alg_napt_mem_free(napt4ic);
#ifdef NAPT_ALLOC_DEBUG 
                printf("@@ napt id free %hu\r\n", --napt4ic_cnt);
#endif
            }
            else
            {
                napt4ic->time_stamp = 0;
            }
        }
        
    }
    /* ���©���ĵ�һ����¼ */
    napt4ic = napt_table_4ic.next;
    if (NULL != napt4ic)
    {
        if (0 == napt4ic->time_stamp)
        {
#ifdef NAPT_TABLE_LIMIT
            napt_table_4ic.cnt--;
#endif
            napt_table_4ic.next = napt4ic->next;
            napt4ic->next = NULL;
            alg_napt_mem_free(napt4ic);
#ifdef NAPT_ALLOC_DEBUG 
            printf("@@ napt id free %hu\r\n", --napt4ic_cnt);
#endif
        }
        else
        {
            napt4ic->time_stamp = 0;
        }
    }
#ifdef NAPT_TABLE_MUTEX_LOCK
    sys_mutex_unlock(napt_table_lock_4ic);
#endif
    return;
}

/*****************************************************************************
 Prototype    : alg_napt_table_check_4tcp
 Description  : tcp napt�����ϻ�������
 Input        : void  
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static void alg_napt_table_check_4tcp(void)
{
    struct napt_addr_4tu *napt4tcp;
    struct napt_addr_4tu *napt4tcp_prev;

    /* tcp */
#ifdef NAPT_TABLE_MUTEX_LOCK
    sys_mutex_lock(napt_table_lock_4tcp);
#endif
    for (napt4tcp_prev = napt_table_4tcp.next;\
         NULL != napt4tcp_prev;\
         napt4tcp_prev = napt4tcp_prev->next)
    {
        napt4tcp = napt4tcp_prev->next;
        if (NULL != napt4tcp)
        {
            if (0 == napt4tcp->time_stamp)
            {
#ifdef NAPT_TABLE_LIMIT
                napt_table_4tcp.cnt--;
#endif
                napt4tcp_prev->next = napt4tcp->next;
                napt4tcp->next = NULL;
                alg_napt_mem_free(napt4tcp);
#ifdef NAPT_ALLOC_DEBUG 
                printf("@@ napt tcp port free %hu\r\n", --napt4tcp_cnt);
#endif
            }
            else
            {
                napt4tcp->time_stamp = 0;
            }
        }
        
    }
    napt4tcp = napt_table_4tcp.next;
    if (NULL != napt4tcp)
    {
        if (0 == napt4tcp->time_stamp)
        {
#ifdef NAPT_TABLE_LIMIT
            napt_table_4tcp.cnt--;
#endif
            napt_table_4tcp.next = napt4tcp->next;
            napt4tcp->next = NULL;
            alg_napt_mem_free(napt4tcp);
#ifdef NAPT_ALLOC_DEBUG 
            printf("@@ napt tcp port free %hu\r\n", --napt4tcp_cnt);
#endif
        }
        else
        {
            napt4tcp->time_stamp = 0;
        }
    }
#ifdef NAPT_TABLE_MUTEX_LOCK
    sys_mutex_unlock(napt_table_lock_4tcp); 
#endif
    return;
}

/*****************************************************************************
 Prototype    : alg_napt_table_check_4udp
 Description  : udp napt�����ϻ�������
 Input        : void  
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static void alg_napt_table_check_4udp(void)
{
    struct napt_addr_4tu *napt4udp;
    struct napt_addr_4tu *napt4udp_prev;

    /* udp */
#ifdef NAPT_TABLE_MUTEX_LOCK
    sys_mutex_lock(napt_table_lock_4udp);
#endif
    for (napt4udp_prev = napt_table_4udp.next;\
         NULL != napt4udp_prev;\
         napt4udp_prev = napt4udp_prev->next)
    {
        napt4udp = napt4udp_prev->next;
        if (NULL != napt4udp)
        {
            if (0 == napt4udp->time_stamp)
            {
#ifdef NAPT_TABLE_LIMIT
                napt_table_4udp.cnt--;
#endif
                napt4udp_prev->next = napt4udp->next;
                napt4udp->next = NULL;
                alg_napt_mem_free(napt4udp);
#ifdef NAPT_ALLOC_DEBUG 
                printf("@@ napt udp port free %hu\r\n", --napt4udp_cnt);
#endif
            }
            else
            {
                napt4udp->time_stamp = 0;
            }
        }
        
    }
    napt4udp = napt_table_4udp.next;
    if (NULL != napt4udp)
    {
        if (0 == napt4udp->time_stamp)
        {
#ifdef NAPT_TABLE_LIMIT
            napt_table_4udp.cnt--;
#endif
            napt_table_4udp.next = napt4udp->next;
            napt4udp->next = NULL;
            alg_napt_mem_free(napt4udp);
#ifdef NAPT_ALLOC_DEBUG 
            printf("@@ napt udp port free %hu\r\n", --napt4udp_cnt);
#endif
        }
        else
        {
            napt4udp->time_stamp = 0;
        }
    }
#ifdef NAPT_TABLE_MUTEX_LOCK
    sys_mutex_unlock(napt_table_lock_4udp); 
#endif
    return;
}

/*****************************************************************************
 Prototype    : alg_napt_port_is_used
 Description  : �ж϶˿��Ƿ��ѱ�ʹ�ã����ṩ��lwip�󶨶˿�ʱʹ��
 Input        : u16 port        �˿ں�
 Output       : None
 Return Value : bool    true    �ѱ�ʹ��
                        false   δ��ʹ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
bool alg_napt_port_is_used(u16 port)
{
    bool is_used = false;
    struct napt_addr_4tu *napt_tcp;
    struct napt_addr_4tu *napt_udp;

#ifdef NAPT_TABLE_MUTEX_LOCK 
    sys_mutex_lock(napt_table_lock_4tcp);
#endif
    NAPT_TABLE_FOREACH(napt_tcp, napt_table_4tcp)
    {
        if (port == napt_tcp->new_port)
        {
            is_used = true;
            break;
        }
    }
#ifdef NAPT_TABLE_MUTEX_LOCK
    sys_mutex_unlock(napt_table_lock_4tcp); 
#endif

    if (true != is_used)
    {
#ifdef NAPT_TABLE_MUTEX_LOCK 
        sys_mutex_lock(napt_table_lock_4udp);
#endif
        NAPT_TABLE_FOREACH(napt_udp, napt_table_4udp)
        {
            if (port == napt_udp->new_port)
            {
                is_used = true;
                break;
            }
        }
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_unlock(napt_table_lock_4udp); 
#endif
    }

    return is_used;
}

/*****************************************************************************
 Prototype    : alg_napt_event_handle
 Description  : napt�����ϻ�������
 Input        : u32 type  ��ʱ���¼�����
 Output       : None
 Return Value : void
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
void alg_napt_event_handle(u32 type)
{
    switch (type)
    {
        case NAPT_TMR_TYPE_TCP:
        {
            alg_napt_table_check_4tcp();
            break;
        }
        case NAPT_TMR_TYPE_UDP:
        {
            alg_napt_table_check_4udp();
            break;
        }
        case NAPT_TMR_TYPE_ICMP:
        {
            alg_napt_table_check_4ic();
            break;
        }
        default:
        {
            break;
        }
    }

    return;
}

/*****************************************************************************
 Prototype    : alg_napt_init
 Description  : Network Address Port Translation��napt�������ʼ��
 Input        : void  
 Output       : None
 Return Value : int      0   �ɹ�
                     other   ʧ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
int alg_napt_init(void)
{
    int err = 0;

    memset(&napt_table_4tcp, 0, sizeof(struct napt_table_head_4tu));
    memset(&napt_table_4udp, 0, sizeof(struct napt_table_head_4tu));
    memset(&napt_table_4ic, 0, sizeof(struct napt_table_head_4ic));

    napt_curr_port = NAPT_LOCAL_PORT_RANGE_START;

#ifdef NAPT_TABLE_MUTEX_LOCK
    err = sys_mutex_new(&napt_table_lock_4tcp);
    if (err)
    {
        LWIP_DEBUGF(NAPT_DEBUG, ("failed to init alg.\n"));
        return err;
    }

    err = sys_mutex_new(&napt_table_lock_4udp);
    if (err)
    {
        LWIP_DEBUGF(NAPT_DEBUG, ("failed to init alg.\n"));
        return err;
    }

    err = sys_mutex_new(&napt_table_lock_4ic);
    if (err)
    {
        LWIP_DEBUGF(NAPT_DEBUG, ("failed to init alg.\n"));
    }
#endif

#ifdef NAPT_ALLOC_DEBUG
    napt4ic_cnt = 0;
    napt4tcp_cnt = 0;
    napt4udp_cnt = 0;
#endif

    return err;
}

/*****************************************************************************
 Prototype    : alg_hdr_16bitsum
 Description  : ����ip����ͷ��16bit�ۼӺ�
 Input        : u16 *buff  ����ͷָ��
                u16 len    ���ĳ���
 Output       : None
 Return Value : u32     sum
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline u32 alg_hdr_16bitsum(const u16 *buff, u16 len)
{
    u32 sum = 0;

    u16 *pos = (u16 *)buff;
    u16 remainder_size = len;

    while (remainder_size > 1)
    {
        sum += *pos ++;
        remainder_size -= NAPT_CHKSUM_16BIT_LEN;
    }

    if (remainder_size > 0)
    {
        sum += *(u8*)pos;
    }

    return sum;
}

/*****************************************************************************
 Prototype    : alg_iphdr_chksum
 Description  : ����ip����ͷУ���
 Input        : u16 *buff  ip����ͷָ��
                u16 len    ip����ͷ����
 Output       : None
 Return Value : u16 chksum
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline u16 alg_iphdr_chksum(const u16 *buff, u16 len)
{
    u32 sum = alg_hdr_16bitsum(buff, len);

    sum = (sum >> 16) + (sum & 0xFFFF); //����16bit���16bit���
    sum += (sum >> 16); //����λ����λ��16bit���16bit �����

    return (u16)(~sum);
}

/*****************************************************************************
 Prototype    : alg_tcpudphdr_chksum
 Description  : ����tcp/udp���ݱ���У���
 Input        : u32 src_addr  ip����ͷ�е�Դip
                u32 dst_addr  ip����ͷ�е�Ŀ��ip
                u8 proto      ip����Э������(ipͷ�е�Э���ֶ�)
                u16 *buff     ip�����е����ݲ����׵�ַ(ipͷ�������)
                u16 len       ip�����е����ݲ��ֳ���(������ipͷ�Ĳ���)
 Output       : None
 Return Value : u16  chksum
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline u16 alg_tcpudphdr_chksum(u32 src_addr, u32 dst_addr, u8 proto,
                                       const u16 *buff, u16 len)
{
    u32 sum = 0;

    /* �ȼ���tcp/dupα�ײ� */
    sum += (src_addr & 0xffffUL);
    sum += ((src_addr >> 16) & 0xffffUL);
    sum += (dst_addr & 0xffffUL);
    sum += ((dst_addr >> 16) & 0xffffUL);
    sum += (u32)htons((u16)proto);/* ����λΪ0�����Ҳ����� */
    sum += (u32)htons(len);

    /* �ټ���tcp/udpͷ�� */
    sum += alg_hdr_16bitsum(buff, len);

    sum = (sum >> 16) + (sum & 0xFFFF); //����16bit���16bit���
    sum += (sum >> 16); //����λ����λ��16bit���16bit �����

    return (u16)(~sum);
}

/*****************************************************************************
 Prototype    : alg_output
 Description  : �ύ���ݱ���ͨ��lwip���ͳ�ȥ
 Input        : struct netif *netif           
                struct ip_hdr *ip_hdr
 Output       : None
 Return Value : int      0   �ɹ�
                        -1   ʧ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline int alg_output(struct netif *netif, const struct ip_hdr *ip_hdr)
{
    int err;
    u16 len;
    ip_addr_t ipaddr;
    struct pbuf *pBuf;

    len = ntohs(ip_hdr->_len);
	pBuf = pbuf_alloc(PBUF_LINK, len, PBUF_RAM);
	if(pBuf == NULL)
	{
		return -1;
	}

    pbuf_take(pBuf, (const void *)ip_hdr, len);

    memset(&ipaddr, 0, sizeof(ip_addr_t));
    ipaddr.addr = ip_hdr->dest.addr;
    
	err = netif->ipfwd_output(pBuf, netif, ipaddr);
	if (0 != err)
	{
        pbuf_free(pBuf);
	}

    return err;
}

/*****************************************************************************
 Prototype    : alg_deliver2lwip
 Description  : �ύ���ݱ���lwip���ش���
 Input        : u8 *bssid            
                u8 *ehdr             
                u16 eth_len          
 Output       : None
 Return Value : int      0   �ɹ�
                        -1   ʧ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
static inline int alg_deliver2lwip(const u8 *bssid, u8 *ehdr, u16 eth_len)
{
    int err;

    err = ethernetif_input(bssid, ehdr, eth_len);

    return err;
}

/*****************************************************************************
 Prototype    : alg_icmp_proc
 Description  : icmp���ݱ���naptת������
 Input        : u8 *bssid                       
                struct ip_hdr *ip_hdr  
                u8 *ehdr    
                u16 eth_len            
 Output       : None
 Return Value : int      0   �ɹ�
                        -1   ʧ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

  Note:
     --------     ap��      -----------     sta��     ---------
     |  AP  |---------------|  APSTA  |---------------|  STA  |
     --------               -----------               ---------
*****************************************************************************/
static int alg_icmp_proc(const u8 *bssid,
                         struct ip_hdr *ip_hdr,
                         u8 *ehdr, u16 eth_len)
{
    int err;
    struct napt_addr_4ic *napt;
    struct icmp_echo_hdr *icmp_hdr;
    struct netif *net_if = tls_get_netif();
    u8 *mac2 = wpa_supplicant_get_mac2();
    u8 iphdr_len;

    iphdr_len = (ip_hdr->_v_hl & 0x0F) * 4;/* ip��ͷ����,��ip��ͷ�ĳ��ȱ�־��4 */
    icmp_hdr = (struct icmp_echo_hdr *)((u8 *)ip_hdr + iphdr_len);

    /* ����sta��� */
    if (0 == compare_ether_addr(bssid, mac2))
    {
        /* Ŀ��ip��ַ��alg�������ύ��alg���ش��� */
        if (ip_hdr->dest.addr == net_if->next->ip_addr.addr)
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
            return err;
        }

        /* ����/����napt���� */
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4ic);
#endif
        napt = alg_napt_get_by_id(icmp_hdr->id);
        if (NULL == napt)
        {
            napt = alg_napt_table_insert_4ic(icmp_hdr->id, ip_hdr->src.addr >> 24);
            if (NULL == napt)
            {
#ifdef NAPT_TABLE_MUTEX_LOCK
                sys_mutex_unlock(napt_table_lock_4ic);
#endif
                return -1;
            }
        }
        else
        {
            alg_napt_table_update_4ic(napt);
        }
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_unlock(napt_table_lock_4ic);
#endif

        ip_hdr->src.addr = net_if->ip_addr.addr;
        ip_hdr->_chksum = 0;
        ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len);

        /* ת����ap��*/
        err = alg_output(net_if, ip_hdr);
    }
    /* ����ap��� */
    else
    {
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4ic);/* �ݲ����Ǽ���ʱ��̫�� */
#endif
        napt = alg_napt_get_by_id(icmp_hdr->id);
        /* ת����sta�� */
        if (NULL != napt)
        {
            //alg_napt_table_update_4ic(napt);

            ip_hdr->dest.addr = ((napt->src_ip) << 24) | (net_if->next->ip_addr.addr & 0x00ffffff);
            ip_hdr->_chksum = 0;
            ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len); 

            err = alg_output(net_if->next, ip_hdr);
        }
        /* �ύ��Ĭ�����ش��� */
        else
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
        }
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_unlock(napt_table_lock_4ic);
#endif
    }

    return err;
}

/*****************************************************************************
 Prototype    : alg_tcp_proc
 Description  : tcp���ݱ���naptת������
 Input        : u8 *bssid                      
                struct ip_hdr *ip_hdr  
                u8 *ehdr    
                u16 eth_len            
 Output       : None
 Return Value : int      0   �ɹ�
                        -1   ʧ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

  Note:
     --------     ap��      -----------     sta��     ---------
     |  AP  |---------------|  APSTA  |---------------|  STA  |
     --------               -----------               ---------
*****************************************************************************/
static int alg_tcp_proc(const u8 *bssid,
                        struct ip_hdr *ip_hdr,
                        u8 *ehdr, u16 eth_len)
{
    int err;
    u8 src_ip;
    struct napt_addr_4tu *napt;
    struct tcp_hdr *tcp_hdr;
    struct netif *net_if = tls_get_netif();
    u8 *mac2 = wpa_supplicant_get_mac2();
    u8 iphdr_len;

    iphdr_len = (ip_hdr->_v_hl & 0x0F) * 4;
    tcp_hdr = (struct tcp_hdr *)((u8 *)ip_hdr + iphdr_len);

    /* ����sta��� */
    if (0 == compare_ether_addr(bssid, mac2))
    {
        /* Ŀ��ip��ַ��alg�������ύ��alg���ش��� */
        if (ip_hdr->dest.addr == net_if->next->ip_addr.addr)
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
            return err;
        }

        /* ����/����napt���� */
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4tcp);
#endif
        src_ip = ip_hdr->src.addr >> 24;
        napt = alg_napt_get_tcp_port_by_src(tcp_hdr->src, src_ip);
        if (NULL == napt)
        {
            napt = alg_napt_table_insert_4tcp(tcp_hdr->src, src_ip);
            if (NULL == napt)
            {
#ifdef NAPT_TABLE_MUTEX_LOCK
                sys_mutex_unlock(napt_table_lock_4tcp);
#endif
                return -1;
            }
        }
        else
        {
            alg_napt_table_update_4tcp(napt);
        }

        ip_hdr->src.addr = net_if->ip_addr.addr;
        ip_hdr->_chksum = 0;
        ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len);

        tcp_hdr->src = napt->new_port;
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_unlock(napt_table_lock_4tcp);
#endif
        tcp_hdr->chksum = 0;
        tcp_hdr->chksum = alg_tcpudphdr_chksum(ip_hdr->src.addr,
                                               ip_hdr->dest.addr,
                                               IP_PROTO_TCP,
                                               (u16 *)tcp_hdr,
                                               ntohs(ip_hdr->_len) - iphdr_len);

        /* ת����ap��*/
        err = alg_output(net_if, ip_hdr);
    }
    /* ����ap��� */
    else
    {
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4tcp);/* �ݲ����Ǽ���ʱ��̫�� */
#endif
        napt = alg_napt_get_tcp_port_by_dest(tcp_hdr->dest);
        /* ת����sta�� */
        if (NULL != napt)
        {
            //alg_napt_table_update_4tcp(napt);

            ip_hdr->dest.addr = (napt->src_ip << 24) | (net_if->next->ip_addr.addr & 0x00ffffff);
            ip_hdr->_chksum = 0;
            ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len);

            tcp_hdr->dest = napt->src_port; 
            tcp_hdr->chksum = 0;
            tcp_hdr->chksum = alg_tcpudphdr_chksum(ip_hdr->src.addr,
                                                   ip_hdr->dest.addr,
                                                   IP_PROTO_TCP,
                                                   (u16 *)tcp_hdr,
                                                   ntohs(ip_hdr->_len) - iphdr_len);

            err = alg_output(net_if->next, ip_hdr);
        }
        /* �ύ��Ĭ�����ش��� */
        else
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
        }
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_unlock(napt_table_lock_4tcp);
#endif
    }

    return err;
}

/*****************************************************************************
 Prototype    : alg_udp_proc
 Description  : udp���ݱ���naptת������
 Input        : u8 *bssid                       
                struct ip_hdr *ip_hdr  
                u8 *ehdr    
                u16 eth_len            
 Output       : None
 Return Value : int      0   �ɹ�
                        -1   ʧ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

  Note:
     --------     ap��      -----------     sta��     ---------
     |  AP  |---------------|  APSTA  |---------------|  STA  |
     --------               -----------               ---------
*****************************************************************************/
static int alg_udp_proc(const u8 *bssid,
                        struct ip_hdr *ip_hdr,
                        u8 *ehdr, u16 eth_len)
{
    int err;
    u8 src_ip;
    struct napt_addr_4tu *napt;
    struct udp_hdr *udp_hdr;
    struct netif *net_if = tls_get_netif();
    u8 *mac2 = wpa_supplicant_get_mac2();
    u8 iphdr_len;

    iphdr_len = (ip_hdr->_v_hl & 0x0F) * 4;
    udp_hdr = (struct udp_hdr *)((u8 *)ip_hdr + iphdr_len);

    /* ����sta��� */
    if (0 == compare_ether_addr(bssid, mac2))
    {
        /* Ŀ��ip��ַ��alg�������ύ��alg���ش��� */
        if (ip_hdr->dest.addr == net_if->next->ip_addr.addr)
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
            return err;
        }

        /* ����/����napt���� */
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4udp);
#endif
        src_ip = ip_hdr->src.addr >> 24;
        napt = alg_napt_get_udp_port_by_src(udp_hdr->src, src_ip);
        if (NULL == napt)
        {
            napt = alg_napt_table_insert_4udp(udp_hdr->src, src_ip);
            if (NULL == napt)
            {
#ifdef NAPT_TABLE_MUTEX_LOCK
                sys_mutex_unlock(napt_table_lock_4udp);
#endif
                return -1;
            }
        }
        else
        {
            alg_napt_table_update_4udp(napt);
        }

        ip_hdr->src.addr = net_if->ip_addr.addr;
        ip_hdr->_chksum = 0;
        ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len);

        udp_hdr->src = napt->new_port;
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_unlock(napt_table_lock_4udp);
#endif

        /* udpУ���Ϊ0˵������Ҫ����У��� */
        if (0 != udp_hdr->chksum)
        {
            udp_hdr->chksum = 0;
            udp_hdr->chksum = alg_tcpudphdr_chksum(ip_hdr->src.addr,
                                                   ip_hdr->dest.addr,
                                                   IP_PROTO_UDP,
                                                   (u16 *)udp_hdr,
                                                   ntohs(ip_hdr->_len) - iphdr_len);
        }

        /* ת����ap��*/
        err = alg_output(net_if, ip_hdr);
    }
    /* ����ap��� */
    else
    {
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4udp);/* �ݲ����Ǽ���ʱ��̫�� */
#endif
        napt = alg_napt_get_udp_port_by_dest(udp_hdr->dest);
        /* ת����sta�� */
        if (NULL != napt)
        {
            //alg_napt_table_update_4udp(napt);

            ip_hdr->dest.addr = (napt->src_ip << 24) | (net_if->next->ip_addr.addr & 0x00ffffff);
            ip_hdr->_chksum = 0;
            ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len);

            udp_hdr->dest = napt->src_port; 
            /* udpУ���Ϊ0˵������Ҫ����У��� */
            if (0 != udp_hdr->chksum)
            {
                udp_hdr->chksum = 0;
                udp_hdr->chksum = alg_tcpudphdr_chksum(ip_hdr->src.addr,
                                                       ip_hdr->dest.addr,
                                                       IP_PROTO_UDP,
                                                       (u16 *)udp_hdr,
                                                       ntohs(ip_hdr->_len) - iphdr_len);
            }

            err = alg_output(net_if->next, ip_hdr);
        }
        /* �ύ��Ĭ�����ش��� */
        else
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
        }
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_unlock(napt_table_lock_4udp);
#endif
    }

    return err;
}

/*****************************************************************************
 Prototype    : alg_input
 Description  : alg��ip���Ĵ�����ں���
 Input        : u8 *bssid            ���ĵ�bssid
                u8 *pkt_body         ��̫�������׵�ַ
                u32 pkt_len          ��̫�����ĳ���
 Output       : None
 Return Value : int      0  �ɹ�
                        -1  ʧ��
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

*****************************************************************************/
int alg_input(const u8 *bssid, u8 *pkt_body, u32 pkt_len)
{
    int err;
    struct ip_hdr *ip_hdr;

    ip_hdr = (struct ip_hdr *)(pkt_body + NAPT_ETH_HDR_LEN);
    switch(ip_hdr->_proto)
    {
        case IP_PROTO_ICMP:/* icmp ���� */
        {
            err = alg_icmp_proc(bssid, ip_hdr, pkt_body, (u16)pkt_len);
            break;
        }
        case IP_PROTO_TCP:/* tcp ���� */
        {
            err = alg_tcp_proc(bssid, ip_hdr, pkt_body, (u16)pkt_len);
            break;
        }
        case IP_PROTO_UDP:/* udp ���� */
        {
            err = alg_udp_proc(bssid, ip_hdr, pkt_body, (u16)pkt_len);
            break;
        }
        default:
        {
            err = -1;
            break;
        }
    }

    return err;
}

#endif

