/******************************************************************************

  Copyright (C) 2015 Winner Micro electronics Co., Ltd.

 ******************************************************************************
  File Name     : alg.h
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
#ifndef __ALG_H__
#define __ALG_H__


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#if TLS_CONFIG_APSTA
/* ============================== configure ===================== */
/* napt表项老化时间, 单位秒，超时删除该记录 */
#define NAPT_TABLE_TIMEOUT           60

/* napt端口池范围，默认范围为15000~19999 */
#define NAPT_LOCAL_PORT_RANGE_START  0x3A98
#define NAPT_LOCAL_PORT_RANGE_END    0x4E1F

/* 表项大小限制，一条10字节，增大这个需对应改大start.s中堆的大小，如1500~17.6K，堆应该从0x00010000-->0x00012000 */
#define NAPT_TABLE_LIMIT
#ifdef  NAPT_TABLE_LIMIT
#define NAPT_TABLE_SIZE_MAX          1000
#endif
/* ============================================================ */


/* 第一次检查第二次才能判断是否老化，所以是( /2 * 1000)ms后超时删除该表项(为了节省内存...) */
#define NAPT_TMR_INTERVAL            ((NAPT_TABLE_TIMEOUT / 2) * 1000UL)

#define NAPT_TMR_TYPE_TCP            0x0
#define NAPT_TMR_TYPE_UDP            0x1
#define NAPT_TMR_TYPE_ICMP           0x2

extern bool alg_napt_port_is_used(u16 port);

extern void alg_napt_event_handle(u32 type);

extern int alg_napt_init(void);

extern int alg_input(const u8 *bssid, u8 *pkt_body, u32 pkt_len);
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __ALG_H__ */
