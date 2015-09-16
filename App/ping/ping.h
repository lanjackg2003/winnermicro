#ifndef __PING_H__
#define __PING_H__

#define TLS_CONFIG_WIFI_PING_TEST   0

#if TLS_CONFIG_WIFI_PING_TEST
struct ping_param{
    char host[64];
    u16 interval;/* ms */
    u8 flags;/* -t */
};

void ping_test_create_task(void);
void ping_test_start(struct ping_param *para);
void ping_test_stop(void);
#endif

#endif /* __PING_H__ */

