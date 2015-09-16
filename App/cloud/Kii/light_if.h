#ifndef LIGHT_IF_H
#define LIGHT_IF_H


#define GPIO_LED1					11

#define LIGHT_PASSWORD_SIZE 32
#define LIGHT_VERSION_NAME_SIZE 16
#define LIGHT_FIRMWARE_UPGRADE_URL_SIZE 256
#define LIGHT_IP_ADDRESS_SIZE 16
#define LIGHT_MODEL_NAME_SIZE 64

// effective fields
#define LIGHT_EFFECTIVE_FIELD_STATE 0x01
#define LIGHT_EFFECTIVE_FIELD_COLOR (0x01 << 1)
#define LIGHT_EFFECTIVE_FIELD_BRIGHTESS (0x01 << 2)
#define LIGHT_EFFECTIVE_FIELD_CT (0x01 << 3)

typedef struct
{
	unsigned char state;      // 0,1
	unsigned char color[3];   // 0..0xffffff
	unsigned char brightness; // 0..100
	unsigned char ct;         // 0..100
	unsigned char effectiveField;
} light_struct;
typedef void (*light_status_event_fn)(light_struct *light);
struct light_status_event
{
    struct dl_list list;
    light_status_event_fn status_callback;
};

int lightIf_init(void);

int lightIf_add_status_event(light_status_event_fn event_fn);
int lightIf_remove_status_event(light_status_event_fn event_fn);

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
int lightIf_control(light_struct light);

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
int lightIf_status(light_struct* light);

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
int lightIf_updateStatus(light_struct light);

/*****************************************************************************
*
*  lightIf_updatePassword
*
*  \param  pwd - the string of password
*
*  \return  0:success; -1: failure
*
*  \brief  Updates light password
*
*****************************************************************************/
int lightIf_updatePassword(char* pwd);

/*****************************************************************************
*
*  lightIf_getPassword
*
*  \param  pwd - the string of password
*
*  \return  0:success; -1: failure
*
*  \brief  Gets light password
*
*****************************************************************************/
int lightIf_getPassword(char* pwd);

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
int lightIf_factoryReset(void);

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
int lightIf_getFirmwareVersion(char* version);

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
int lightIf_firmwareUpgrade(char* url, char* version);

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
int lightIf_getIPAddress(char* ipAddress);

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
int lightIf_getIModelName(char* name);

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
int lightIf_getMacAddr(char* mac_addr);

#endif
