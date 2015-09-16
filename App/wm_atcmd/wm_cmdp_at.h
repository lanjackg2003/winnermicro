/**************************************************************************
 * File Name                   : tls_cmdp_at.h
 * Author                       :
 * Version                      :
 * Date                          :
 * Description                 :
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd. 
 * All rights reserved.
 *
 ***************************************************************************/

#include "wm_cmdp.h"
#if (GCC_COMPILE==1)
#include "wm_cmdp_hostif_gcc.h"
#else
#include "wm_cmdp_hostif.h"
#endif
#ifndef TLS_CMDP_AT_H
#define TLS_CMDP_AT_H

#define ATCMD_OP_NULL       0
#define ATCMD_OP_EQ         1    /* = */
#define ATCMD_OP_EP         2    /* =! , update flash*/
#define ATCMD_OP_QU         3    /* =? */

#define AT_RESP_OK_STR_LEN    3
#define AT_RESP_ERR_STR_LEN   4

typedef int (* atcmd_proc)(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len);

struct tls_atcmd_t {
    char   *name;
    u8   flag;
    int (* proc_func)(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len);
};

int atcmd_err_resp(char *buf, int err_code);
int atcmd_ok_resp(char *buf);
static int atcmd_nop_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len);

int tls_atcmd_parse(struct tls_atcmd_token_t *tok, char *buf, u32 len);
int tls_atcmd_exec(struct tls_atcmd_token_t *tok,
        char *res_rsp, u32 *res_len);

#endif /* end of TLS_CMDP_AT_H */
