#include "wm_config.h"

#if TLS_CONFIG_CLOUD
#include "wm_task.h"
#include "wm_socket.h"

static sys_mbox_t task_mbox[TLS_TASK_ALL_COUNT];

static void
task_thread(void *arg)
{
  struct task_msg *msg;
  int num = ((int)arg);
  while (1) {                          /* MAIN Loop */
    /* wait for a message, timeouts are processed while waiting */
    sys_timeouts_mbox_fetch_p(num + 1, task_mbox[num], (void **)&msg);
    switch (msg->type) {
    case TASK_MSG_TIMEOUT:
      sys_timeout_p(num + 1, msg->msg.tmo.msecs, msg->msg.tmo.h, msg->msg.tmo.arg);
      tls_mem_free(msg);
      break;
    case TASK_MSG_UNTIMEOUT:
      sys_untimeout_p(num + 1, msg->msg.tmo.h, msg->msg.tmo.arg);
      tls_mem_free(msg);
      break;
    case TASK_MSG_CALLBACK:
      msg->msg.cb.function(msg->msg.cb.ctx);
      tls_mem_free(msg);
      break;
    default:
      break;
    }
  }
}

err_t tls_task_run(struct task_parameter *task_param)
{
  int num;
  u8 * task_stk;
  num = task_param->task_id;
  if(sys_mbox_new(&task_mbox[num], task_param->mbox_size) != ERR_OK) {
    return -1;
  }
  task_stk = task_param->stk_start;
  tls_os_task_create(NULL, task_param->name,
                       task_thread,
                       (void *)(num),
                       (void *)task_stk,
                       task_param->stk_size * sizeof(u32),
                       TLS_TASK_START_PRIO+num,
                       0);
	return 0;
}

err_t
tls_task_callback_with_block(u8 task_id, start_routine function, void *ctx, u8_t block)
{
  struct task_msg *msg;

  if (sys_mbox_valid(task_mbox[task_id])) {
    msg = (struct task_msg *)tls_mem_alloc(sizeof(struct task_msg));
    if (msg == NULL) {
      return ERR_MEM;
    }

    msg->type = TASK_MSG_CALLBACK;
    msg->msg.cb.function = function;
    msg->msg.cb.ctx = ctx;
    if (block) {
      sys_mbox_post(task_mbox[task_id], msg);
    } else {
      if (sys_mbox_trypost(task_mbox[task_id], msg) != ERR_OK) {
        tls_mem_free(msg);
        return ERR_MEM;
      }
    }
    return ERR_OK;
  }
  return ERR_VAL;
}

err_t
tls_task_add_timeout(u8 task_id, u32_t msecs, sys_timeout_handler h, void *arg)
{
  struct task_msg *msg;

  if (sys_mbox_valid(task_mbox[task_id])) {
    msg = (struct task_msg *)tls_mem_alloc(sizeof(struct task_msg));
    if (msg == NULL) {
      return ERR_MEM;
    }

    msg->type = TASK_MSG_TIMEOUT;
    msg->msg.tmo.msecs = msecs;
    msg->msg.tmo.h = h;
    msg->msg.tmo.arg = arg;
    sys_mbox_post(task_mbox[task_id], msg);
    return ERR_OK;
  }
  return ERR_VAL;
}

err_t
tls_task_untimeout(u8 task_id, sys_timeout_handler h, void *arg)
{
  struct task_msg *msg;

  if (sys_mbox_valid(task_mbox[task_id])) {
    msg = (struct task_msg *)tls_mem_alloc(sizeof(struct task_msg));
    if (msg == NULL) {
      return ERR_MEM;
    }

    msg->type = TASK_MSG_UNTIMEOUT;
    msg->msg.tmo.h = h;
    msg->msg.tmo.arg = arg;
    sys_mbox_post(task_mbox[task_id], msg);
    return ERR_OK;
  }
  return ERR_VAL;
}
#endif //TLS_CONFIG_CLOUD

