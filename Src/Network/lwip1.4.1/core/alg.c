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

/* 打印napt表项统计信息 */
//#define NAPT_ALLOC_DEBUG
#ifdef  NAPT_ALLOC_DEBUG
static u16 napt4ic_cnt;
static u16 napt4tcp_cnt;
static u16 napt4udp_cnt;
#endif

/* 以太网报文头固定大小, 14字节 */
#define NAPT_ETH_HDR_LEN             sizeof(struct ethhdr)

/* 校验和16bit长度, 2字节 */
#define NAPT_CHKSUM_16BIT_LEN        sizeof(u16)

/* 单链表表项遍历宏 */
#define NAPT_TABLE_FOREACH(pos, head)\
         for (pos = head.next; NULL != pos; pos = pos->next)

/* napt tcp/udp 表项结构 */
struct napt_addr_4tu{
    struct napt_addr_4tu *next;
    u16 src_port;
    u16 new_port;
    u8 src_ip;
    u8 time_stamp;
};

/* napt icmp 表项结构 */
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

/* napt表项链表头 */
static struct napt_table_head_4tu napt_table_4tcp;
static struct napt_table_head_4tu napt_table_4udp;
static struct napt_table_head_4ic napt_table_4ic;

/* napt表项链表锁，整个过程都在lwip一个任务的流程里处理，所以无需加锁 */
//#define NAPT_TABLE_MUTEX_LOCK
#ifdef  NAPT_TABLE_MUTEX_LOCK
static sys_mutex_t napt_table_lock_4tcp;
static sys_mutex_t napt_table_lock_4udp;
static sys_mutex_t napt_table_lock_4ic;
#endif

/* 端口池游标 */
static u16 napt_curr_port;

/*****************************************************************************
 Prototype    : alg_napt_mem_alloc
 Description  : 分配一条表项内存
 Input        : u32 size        待分配的内存大小
 Output       : None
 Return Value : void*    NULL   分配失败
                        !NULL   分配成功
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
 Description  : 释放一条表项内存
 Input        : void *p        待释放的内存
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
 Description  : 检查napt表项是否已达最大值
 Input        : void  
 Output       : None
 Return Value : bool    true   表项已满
                        false  表项未满
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
 Description  : 分配一个napt端口号
 Input        : void  
 Output       : None
 Return Value : u16    0      失败
                       other  成功
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
 Description  : 通过icmp echo id查找napt表项
 Input        : u16 id          icmp echo id
 Output       : None
 Return Value : struct napt_addr_4ic *      NULL   失败
                                           !NULL   成功
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
 Description  : 创建napt表项
 Input        : u16 id          源id
                u8  ip          源ip地址
 Output       : None
 Return Value : struct napt_addr_4ic *      NULL   失败
                                           !NULL   成功
 Note         : icmp报文较少，暂不加数量限制
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
 Description  : 刷新napt表项时间戳
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
 Description  : 根据目的端口号查找napt表项
 Input        : u16 port    目的端口号
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   失败
                                       !NULL   成功
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
 Description  : 根据源端口号和源ip地址查找napt表项
 Input        : u16 port    源端口号
                u8  ip      源ip地址
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   失败
                                       !NULL   成功
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
 Description  : 创建napt表项
 Input        : u16 src_port    源端口号
                u8  ip          源ip地址
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   失败
                                            !NULL   成功
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
 Description  : 刷新napt表项时间戳
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
 Description  : 根据目的端口号查找napt表项
 Input        : u16 port    目的端口号
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   失败
                                            !NULL   成功
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
 Description  : 根据源端口号和源ip地址查找napt表项
 Input        : u16 port    源端口号
                u8  ip      源ip地址
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   失败
                                            !NULL   成功
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
 Description  : 创建napt表项
 Input        : u16 src_port    源端口号
                u8  ip          源ip地址
 Output       : None
 Return Value : struct napt_addr_4tu *      NULL   失败
                                            !NULL   成功
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
 Description  : 刷新napt表项时间戳
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
 Description  : icmp napt表项老化处理函数
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
    /* 这种遍历方式会漏掉第一条记录 */
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
    /* 检查漏掉的第一条记录 */
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
 Description  : tcp napt表项老化处理函数
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
 Description  : udp napt表项老化处理函数
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
 Description  : 判断端口是否已被使用，仅提供给lwip绑定端口时使用
 Input        : u16 port        端口号
 Output       : None
 Return Value : bool    true    已被使用
                        false   未被使用
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
 Description  : napt表项老化处理函数
 Input        : u32 type  定时器事件类型
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
 Description  : Network Address Port Translation（napt）表项初始化
 Input        : void  
 Output       : None
 Return Value : int      0   成功
                     other   失败
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
 Description  : 计算ip报文头的16bit累加和
 Input        : u16 *buff  报文头指针
                u16 len    报文长度
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
 Description  : 计算ip报文头校验和
 Input        : u16 *buff  ip报文头指针
                u16 len    ip报文头长度
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

    sum = (sum >> 16) + (sum & 0xFFFF); //将高16bit与低16bit相加
    sum += (sum >> 16); //将进位到高位的16bit与低16bit 再相加

    return (u16)(~sum);
}

/*****************************************************************************
 Prototype    : alg_tcpudphdr_chksum
 Description  : 计算tcp/udp数据报文校验和
 Input        : u32 src_addr  ip报文头中的源ip
                u32 dst_addr  ip报文头中的目的ip
                u8 proto      ip报文协议类型(ip头中的协议字段)
                u16 *buff     ip报文中的数据部分首地址(ip头后的数据)
                u16 len       ip报文中的数据部分长度(不包含ip头的部分)
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

    /* 先计算tcp/dup伪首部 */
    sum += (src_addr & 0xffffUL);
    sum += ((src_addr >> 16) & 0xffffUL);
    sum += (dst_addr & 0xffffUL);
    sum += ((dst_addr >> 16) & 0xffffUL);
    sum += (u32)htons((u16)proto);/* 保留位为0故暂且不考虑 */
    sum += (u32)htons(len);

    /* 再计算tcp/udp头部 */
    sum += alg_hdr_16bitsum(buff, len);

    sum = (sum >> 16) + (sum & 0xFFFF); //将高16bit与低16bit相加
    sum += (sum >> 16); //将进位到高位的16bit与低16bit 再相加

    return (u16)(~sum);
}

/*****************************************************************************
 Prototype    : alg_output
 Description  : 提交数据报文通过lwip发送出去
 Input        : struct netif *netif           
                struct ip_hdr *ip_hdr
 Output       : None
 Return Value : int      0   成功
                        -1   失败
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
 Description  : 提交数据报文lwip网关处理
 Input        : u8 *bssid            
                u8 *ehdr             
                u16 eth_len          
 Output       : None
 Return Value : int      0   成功
                        -1   失败
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
 Description  : icmp数据报文napt转换函数
 Input        : u8 *bssid                       
                struct ip_hdr *ip_hdr  
                u8 *ehdr    
                u16 eth_len            
 Output       : None
 Return Value : int      0   成功
                        -1   失败
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

  Note:
     --------     ap侧      -----------     sta侧     ---------
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

    iphdr_len = (ip_hdr->_v_hl & 0x0F) * 4;/* ip报头长度,即ip报头的长度标志乘4 */
    icmp_hdr = (struct icmp_echo_hdr *)((u8 *)ip_hdr + iphdr_len);

    /* 来自sta侧的 */
    if (0 == compare_ether_addr(bssid, mac2))
    {
        /* 目标ip地址是alg网关则提交给alg网关处理 */
        if (ip_hdr->dest.addr == net_if->next->ip_addr.addr)
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
            return err;
        }

        /* 创建/更新napt表项 */
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

        /* 转发到ap侧*/
        err = alg_output(net_if, ip_hdr);
    }
    /* 来自ap侧的 */
    else
    {
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4ic);/* 暂不考虑加锁时间太长 */
#endif
        napt = alg_napt_get_by_id(icmp_hdr->id);
        /* 转发到sta侧 */
        if (NULL != napt)
        {
            //alg_napt_table_update_4ic(napt);

            ip_hdr->dest.addr = ((napt->src_ip) << 24) | (net_if->next->ip_addr.addr & 0x00ffffff);
            ip_hdr->_chksum = 0;
            ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len); 

            err = alg_output(net_if->next, ip_hdr);
        }
        /* 提交给默认网关处理 */
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
 Description  : tcp数据报文napt转换函数
 Input        : u8 *bssid                      
                struct ip_hdr *ip_hdr  
                u8 *ehdr    
                u16 eth_len            
 Output       : None
 Return Value : int      0   成功
                        -1   失败
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

  Note:
     --------     ap侧      -----------     sta侧     ---------
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

    /* 来自sta侧的 */
    if (0 == compare_ether_addr(bssid, mac2))
    {
        /* 目标ip地址是alg网关则提交给alg网关处理 */
        if (ip_hdr->dest.addr == net_if->next->ip_addr.addr)
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
            return err;
        }

        /* 创建/更新napt表项 */
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

        /* 转发到ap侧*/
        err = alg_output(net_if, ip_hdr);
    }
    /* 来自ap侧的 */
    else
    {
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4tcp);/* 暂不考虑加锁时间太长 */
#endif
        napt = alg_napt_get_tcp_port_by_dest(tcp_hdr->dest);
        /* 转发到sta侧 */
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
        /* 提交给默认网关处理 */
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
 Description  : udp数据报文napt转换函数
 Input        : u8 *bssid                       
                struct ip_hdr *ip_hdr  
                u8 *ehdr    
                u16 eth_len            
 Output       : None
 Return Value : int      0   成功
                        -1   失败
 ------------------------------------------------------------------------------
 
  History        :
  1.Date         : 2015/3/10
    Author       : Li Limin, lilm@winnermicro.com
    Modification : Created function

  Note:
     --------     ap侧      -----------     sta侧     ---------
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

    /* 来自sta侧的 */
    if (0 == compare_ether_addr(bssid, mac2))
    {
        /* 目标ip地址是alg网关则提交给alg网关处理 */
        if (ip_hdr->dest.addr == net_if->next->ip_addr.addr)
        {
            err = alg_deliver2lwip(bssid, ehdr, eth_len);
            return err;
        }

        /* 创建/更新napt表项 */
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

        /* udp校验和为0说明不需要计算校验和 */
        if (0 != udp_hdr->chksum)
        {
            udp_hdr->chksum = 0;
            udp_hdr->chksum = alg_tcpudphdr_chksum(ip_hdr->src.addr,
                                                   ip_hdr->dest.addr,
                                                   IP_PROTO_UDP,
                                                   (u16 *)udp_hdr,
                                                   ntohs(ip_hdr->_len) - iphdr_len);
        }

        /* 转发到ap侧*/
        err = alg_output(net_if, ip_hdr);
    }
    /* 来自ap侧的 */
    else
    {
#ifdef NAPT_TABLE_MUTEX_LOCK
        sys_mutex_lock(napt_table_lock_4udp);/* 暂不考虑加锁时间太长 */
#endif
        napt = alg_napt_get_udp_port_by_dest(udp_hdr->dest);
        /* 转发到sta侧 */
        if (NULL != napt)
        {
            //alg_napt_table_update_4udp(napt);

            ip_hdr->dest.addr = (napt->src_ip << 24) | (net_if->next->ip_addr.addr & 0x00ffffff);
            ip_hdr->_chksum = 0;
            ip_hdr->_chksum = alg_iphdr_chksum((u16 *)ip_hdr, iphdr_len);

            udp_hdr->dest = napt->src_port; 
            /* udp校验和为0说明不需要计算校验和 */
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
        /* 提交给默认网关处理 */
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
 Description  : alg的ip报文处理入口函数
 Input        : u8 *bssid            报文的bssid
                u8 *pkt_body         以太网报文首地址
                u32 pkt_len          以太网报文长度
 Output       : None
 Return Value : int      0  成功
                        -1  失败
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
        case IP_PROTO_ICMP:/* icmp 报文 */
        {
            err = alg_icmp_proc(bssid, ip_hdr, pkt_body, (u16)pkt_len);
            break;
        }
        case IP_PROTO_TCP:/* tcp 报文 */
        {
            err = alg_tcp_proc(bssid, ip_hdr, pkt_body, (u16)pkt_len);
            break;
        }
        case IP_PROTO_UDP:/* udp 报文 */
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

