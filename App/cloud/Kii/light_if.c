#include <string.h>
#include "wm_include.h"

#include "light.h"
#include "light_if.h"


static struct light_status_event light_status_event_list;

int lightIf_init(void)
{
	memset(&light_status_event_list, 0, sizeof(struct light_status_event));
	dl_list_init(&light_status_event_list.list);
	return 0;
}

int lightIf_add_status_event(light_status_event_fn event_fn)
{
    u32 cpu_sr;
    struct light_status_event *evt;
    //if exist, remove from event list first.
    lightIf_remove_status_event(event_fn);
    evt = tls_mem_alloc(sizeof(struct light_status_event));
    if(evt==NULL)
        return -1;
    memset(evt, 0, sizeof(struct light_status_event));
    evt->status_callback = event_fn;
    cpu_sr = tls_os_set_critical();
    dl_list_add_tail(&light_status_event_list.list, &evt->list);
    tls_os_release_critical(cpu_sr);

	return 0;
}
int lightIf_remove_status_event(light_status_event_fn event_fn)
{
    struct light_status_event *status_event;
    bool is_exist = FALSE;
    u32 cpu_sr;
    if(dl_list_empty(&light_status_event_list.list))
        return 0;
    dl_list_for_each(status_event, &light_status_event_list.list, struct light_status_event, list)
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

/*****************************************************************************
*
*  lightIf_control
*
*  \param  light - light struct
*
*  \return  0:success; -1: failure
*
*  \brief  Controls light
*
*****************************************************************************/
int lightIf_control(light_struct light)
{
	struct light_status_event *status_event;
	tls_gpio_cfg(GPIO_LED1, TLS_GPIO_DIR_OUTPUT, TLS_GPIO_ATTR_FLOATING);
	tls_gpio_write(GPIO_LED1, light.state);
	dl_list_for_each(status_event, &light_status_event_list.list, struct light_status_event, list)
	{
		if(status_event->status_callback != NULL)
		{
			status_event->status_callback(&light);
		}
    	}
	return 0;
}

/*****************************************************************************
*
*  lightIf_status
*
*  \param  *light - light struct poiter
*
*  \return  0:success; -1: failure
*
*  \brief  Gets light status
*
*****************************************************************************/
int lightIf_status(light_struct* light)
{
	light->state = tls_gpio_read(GPIO_LED1);
	light->brightness = 90;
	light->color[0] = 0xf1;
	light->color[1] = 0x88;
	light->color[2] = 0x77;
	light->ct = 80;
	light->effectiveField = LIGHT_EFFECTIVE_FIELD_STATE | LIGHT_EFFECTIVE_FIELD_COLOR | LIGHT_EFFECTIVE_FIELD_BRIGHTESS;
	return 0;
}

/*****************************************************************************
*
*  lightIf_updateStatus
*
*  \param  light - light struct
*
*  \return  0:success; -1: failure
*
*  \brief  Updates light status to cloud
*
*****************************************************************************/
int lightIf_updateStatus(light_struct light)
{
#if DEMO_KII
	return light_updateStatus(light);
#else
	return 0;
#endif
}

/*****************************************************************************
*
*  lightIf_updatePassword
*
*  \param  pwd - the string of password, it should be allowed to be NULL
*
*  \return  0:success; -1: failure
*
*  \brief  Updates light password
*
*****************************************************************************/
int lightIf_updatePassword(char* pwd)
{
	return 0;
}

/*****************************************************************************
*
*  lightIf_getPassword
*
*  \param  pwd - the string of password, returns NULL if no password
*
*  \return  0:success; -1: failure
*
*  \brief  Gets light password
*
*****************************************************************************/
int lightIf_getPassword(char* pwd)
{
	strcpy(pwd, "123456");
	return 0;
}

/*****************************************************************************
*
*  lightIf_factoryReset
*
*  \param  none
*
*  \return  0:success; -1: failure
*
*  \brief  Factory reset
*
*****************************************************************************/
int lightIf_factoryReset(void)
{
	return 0;
}

/*****************************************************************************
*
*  lightIf_getFirmwareVersion
*
*  \param  version - the string of version name
*
*  \return  0:success; -1: failure
*
*  \brief  gets the current firmware version
*
*****************************************************************************/
int lightIf_getFirmwareVersion(char* version)
{
	strcpy(version, "1.1.00");
	return 0;
}

/*****************************************************************************
*
*  lightIf_firmwareUpgrade
*
*  \param  url - the string of url for downloading firmware
*              version - the string of version name to be upgraded
*
*  \return  0:success; -1: failure
*
*  \brief  Upgrades firmware
*
*****************************************************************************/
int lightIf_firmwareUpgrade(char* url, char* version)
{
// check and compare version with the old one
	return 0;
}

/*****************************************************************************
*
*  lightIf_getIPAddress
*
*  \param  ipAddress - the string of IP adress
*
*  \return  0:success; -1: failure
*
*  \brief  Gets external IP address
*
*****************************************************************************/
int lightIf_getIPAddress(char* ipAddress)
{
	strcpy(ipAddress, "192.168.1.98");
	return 0;
}

/*****************************************************************************
*
*  lightIf_getIModelName
*
*  \param  name - the string of model name
*
*  \return  0:success; -1: failure
*
*  \brief  Gets model name
*
*****************************************************************************/
int lightIf_getIModelName(char* name)
{
	strcpy(name, "07-00-XXXX");
	return 0;
}

/*****************************************************************************
*
*  lightIf_getMacAddr
*
*  \param  mac_addr - the string of mac address
*
*  \return  0:success; -1: failure
*
*  \brief  Gets mac address
*
*****************************************************************************/
int lightIf_getMacAddr(char* mac_addr)
{
#if 1
	unsigned char addr[8];
	int i;

	memset(addr,0,sizeof(addr));
	tls_get_mac_addr(addr);
	for(i=0; i<6; i++)
	{
		sprintf(mac_addr+strlen(mac_addr), "%02X", addr[i]);
	}
	return 0;

#else
	strcpy(mac_addr, "78B3B90FFEF1");
	return 0;
#endif
}
