#ifndef __WM_TASK_H__
#define __WM_TASK_H__

#include "sys_arch.h"
#include "timers.h"
//#include "ithread.h"
#include "wm_type_def.h"
#if TLS_CONFIG_CLOUD

#define TLS_TASK_START_PRIO 50
#define TLS_TASK_ALL_COUNT   12

/****************************************************************************
 * Name: start_routine
 *
 *  Description:
 *      Thread start routine 
 *      Internal Use Only.
 ***************************************************************************/
typedef void *(*start_routine)(void *arg);

enum task_msg_type {
  TASK_MSG_TIMEOUT,
  TASK_MSG_UNTIMEOUT,
  TASK_MSG_CALLBACK
};

struct task_msg {
  enum task_msg_type type;
  sys_sem_t *sem;
  union {
    struct {
      start_routine function;
      void *ctx;
    } cb;
    struct {
      u32_t msecs;
      sys_timeout_handler h;
      void *arg;
    } tmo;
  } msg;
};

struct task_parameter{
	u8 task_id;
	const char * name;
	u8 *stk_start;
	u32 stk_size;
	u8 mbox_size;
};

err_t
tls_task_run(struct task_parameter * task_param);
err_t
tls_task_callback_with_block(u8 task_id, start_routine function, void *ctx, u8_t block);
err_t
tls_task_add_timeout(u8 task_id, u32_t msecs, sys_timeout_handler h, void *arg);
err_t
tls_task_untimeout(u8 task_id, sys_timeout_handler h, void *arg);

#endif //TLS_CONFIG_CLOUD
#endif

