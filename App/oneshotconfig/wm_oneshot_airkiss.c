#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "wm_include.h"
#include "airkiss.h"
#include "wm_wifi_oneshot.h"

#if TLS_CONFIG_AIRKISS_MODE_ONESHOT

/* aes-128����key */
#if AIRKISS_ENABLE_CRYPT
#define ONESHOT_AIRKISS_AES_KEY          "winnermicro_wifi"
#endif

/* 0-->12��Ӧ1-->13�ŵ� */
#define ONESHOT_AIRKISS_CHANNEL_ID_MIN    0
#define ONESHOT_AIRKISS_CHANNEL_ID_MAX    12

/* udp�㲥�˿� */
#define ONESHOT_AIRKISS_REMOTE_PORT      10000

/* udp�㲥����Ŀ */
#define ONESHOT_AIRKISS_REPLY_CNT_MAX    20

/* udp�㲥������ */
static u8 random4reply = 0;

/* ����ѯ�л��ŵ�ʱָʾ��ǰ�ŵ� */
static u8 curr_channel = ONESHOT_AIRKISS_CHANNEL_ID_MIN;

/* ��ѯ�л��ŵ���ʱ�� */
static tls_os_timer_t *tmier4switchch = NULL;

/* airkiss������ */
static airkiss_context_t *pakcontext  = NULL;

/* airkiss�������ܺ��� */
static airkiss_config_t  *pakconfig   = NULL;

#if TLS_CONFIG_SOCKET_RAW
void oneshot_airkiss_send_reply(void)
{
	u8 idx;
	int socket_num = 0;
	struct tls_socket_desc socket_desc;

    /* 13.�����ɹ�֮����10000�˿ڹ㲥����udp���ģ�ͨ��һ�������Ѿ����óɹ� */
	memset(&socket_desc, 0, sizeof(struct tls_socket_desc));
	socket_desc.cs_mode = SOCKET_CS_MODE_CLIENT;
	socket_desc.protocol = SOCKET_PROTO_UDP;
	for(idx = 0; idx < 4; idx++){
		socket_desc.ip_addr[idx] = 255;
	}
	socket_desc.port = ONESHOT_AIRKISS_REMOTE_PORT;
	socket_num = tls_socket_create(&socket_desc);
	//printf("create skt %d: send udp broadcast to airkiss.\r\n", socket_num);
	tls_os_time_delay(50);
	for(idx = 0; idx < ONESHOT_AIRKISS_REPLY_CNT_MAX; idx++)/* ���ٷ���20�� */
	{
	    /* ���ͽ��Ϊ����get_result����randomֵ��һ���ֽ�udp���ݰ� */
		tls_socket_send(socket_num, &random4reply, sizeof(random4reply));
		tls_os_time_delay(50);
	}
	tls_socket_close(socket_num);

	return;
}
#endif

static void oneshot_airkiss_finish(void)
{
    int ret = -1;
    airkiss_result_t result;
#if TLS_CONFIG_APSTA
    int ssid4ap_len = 0;
    u8 mac_addr[ETH_ALEN];
    u8 ssid4ap[33];
#endif

    /* 10.�������������ݺ��airkiss��ȡ���������� */
    memset(&result, 0, sizeof(airkiss_result_t));
    ret = airkiss_get_result(pakcontext, &result);
    if (0 != ret)
    {
        //printf("failed to get airkiss result %d.\r\n", ret);
        return;
    }

    //printf("start connect: ssid '%s', pwd '%s', random '%hhu'.\r\n", result.ssid, result.pwd, result.random);
    random4reply = result.random;

    /* 11.�ر�һ�����á��ر�ǰ������get_result��������ǰ�ͷ�airkiss�����Ļᵼ��get_resultʧ�� */
    tls_wifi_set_oneshot_flag(0);

    /* 12.ʹ�õõ������ü��� */
#if CONFIG_NORMAL_MODE_ONESHOT
    ret = tls_wifi_connect((u8 *)(result.ssid), result.ssid_length, (u8 *)(result.pwd), result.pwd_length);
#else
#if TLS_CONFIG_APSTA
    ssid4ap[0] = '\0';
    memset(mac_addr, 0, ETH_ALEN);
    tls_get_mac_addr(mac_addr);
    ssid4ap_len = sprintf((char *)ssid4ap, "apsta_softap_%02hhX%02hhX", mac_addr[ETH_ALEN - 2], mac_addr[ETH_ALEN - 1]);
    ret = tls_wifi_apsta_start((u8 *)(result.ssid), result.ssid_length, (u8 *)(result.pwd), result.pwd_length, ssid4ap, ssid4ap_len);
#else
    ret = tls_wifi_connect((u8 *)(result.ssid), result.ssid_length, (u8 *)(result.pwd), result.pwd_length);
#endif
#endif
    if (WM_SUCCESS != ret)
    {
        //printf("failed to connect net, airkiss join net failed.\r\n");
    }

    return;
}

static void oneshot_airkiss_swchn_callback(void *ptmr, void *parg)
{
    if (curr_channel >= ONESHOT_AIRKISS_CHANNEL_ID_MAX)
        curr_channel = ONESHOT_AIRKISS_CHANNEL_ID_MIN;
    else
        curr_channel++;

    tls_wifi_change_chanel(curr_channel);

    return;
}

static void oneshot_airkiss_fill_config(airkiss_config_t *pconfig)
{
    pconfig->memset = (airkiss_memset_fn)&memset;
    pconfig->memcpy = (airkiss_memcpy_fn)&memcpy;
    pconfig->memcmp = (airkiss_memcmp_fn)&memcmp;
    //pconfig->printf = (airkiss_printf_fn)&printf;

    return;
}

void tls_airkiss_recv(u8 *data, u16 data_len)
{
    int ret;

    /* 7.�����н��յ��ı��Ĵ���airkiss���� */
    ret = airkiss_recv(pakcontext, data, data_len);
    if (ret == AIRKISS_STATUS_CHANNEL_LOCKED)/* 8.�Ѿ��������˵�ǰ���ŵ�����ʱ��������ѯ�л��ŵ������� */
    {
        //printf("stoped switch channel.\r\n");
        tls_os_timer_stop(tmier4switchch);
    }
    else if (ret == AIRKISS_STATUS_COMPLETE)/* 9.�Ѿ����յ������е��������� */
    {
        //printf("airkiss recv finish.\r\n");
        oneshot_airkiss_finish();
    }

    return;
}

void tls_airkiss_start(void)
{
    int ret = -1;

    //printf("start airkiss oneshot config...\r\n"
    //       "airkiss version: %s\r\n", airkiss_version());

    /* 1.�������������� */
    if (NULL == pakcontext)
    {
        pakcontext = tls_mem_alloc(sizeof(airkiss_context_t));
        if (NULL == pakcontext)
        {
            //printf("failed to malloc airkiss context.\r\n");
            return;
        }
    }

    /* 2.���һЩ���ܺ��� */
    if (NULL == pakconfig)
    {
        pakconfig = tls_mem_alloc(sizeof(airkiss_config_t));
        if (NULL == pakconfig)
        {
            //printf("failed to malloc airkiss config.\r\n");
            tls_mem_free(pakcontext);
            pakcontext = NULL;
            return;
        }
    }

    memset(pakcontext, 0, sizeof(airkiss_context_t));
    memset(pakconfig,  0, sizeof(airkiss_config_t));
    oneshot_airkiss_fill_config(pakconfig);

    /* 3.��ʼ��airkiss */
    ret = airkiss_init(pakcontext, pakconfig);
    if (0 != ret)
    {
        //printf("failed to init airkiss.\r\n");
        tls_mem_free(pakcontext);
        pakcontext = NULL;
        tls_mem_free(pakconfig);
        pakconfig  = NULL;
        return;
    }

    /* 4.����aes������Կ������Ҫ���ܵĻ� */
#if AIRKISS_ENABLE_CRYPT
    ret = airkiss_set_key(pakcontext, ONESHOT_AIRKISS_AES_KEY, strlen(ONESHOT_AIRKISS_AES_KEY));
    if (0 != ret)
    {
        //printf("failed to set airkiss aes key.\r\n");
        tls_mem_free(pakcontext);
        pakcontext = NULL;
        tls_mem_free(pakconfig);
        pakconfig  = NULL;
        return;
    }
#endif

    /* 5.����һ���л��ŵ���ѭ����ʱ����100ms */
    if (NULL == tmier4switchch)
    {
        ret = tls_os_timer_create(&tmier4switchch, oneshot_airkiss_swchn_callback, NULL, 10, true, NULL);
        if (TLS_OS_SUCCESS != ret)
        {
            //printf("failed to create switch channel timer for airkiss.\r\n");
            tls_mem_free(pakcontext);
            pakcontext = NULL;
            tls_mem_free(pakconfig);
            pakconfig  = NULL;
            return;
        }
    }

    /* 6.��ʼ��ѯ�л��ŵ�����airkiss���ñ��� */
    curr_channel = ONESHOT_AIRKISS_CHANNEL_ID_MIN;
    tls_os_timer_start(tmier4switchch);

    return;
}

void tls_airkiss_stop(void)
{
    //printf("stop airkiss oneshot config...\r\n");

    if (NULL != tmier4switchch)
    {
        tls_os_timer_stop(tmier4switchch);
    }

    if (NULL != pakconfig)
    {
        tls_mem_free(pakconfig);
        pakconfig = NULL;
    }

    if (NULL != pakcontext)
    {
        tls_mem_free(pakcontext);
        pakcontext = NULL;
    }

    return;
}
#endif

