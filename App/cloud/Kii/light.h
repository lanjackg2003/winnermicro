#ifndef LIGHT_H
#define LIGHT_H

#include "light_if.h"

/*
// for test
#define STR_SITE_JP "JP"
#define STR_APPID_JP "06e806e2"
#define STR_APPKEY_JP "31afdcdfd72ade025559176a40a20875"
*/

#define STR_SITE_CN "CN"
#define STR_APPID_CN "47b45d43"
#define STR_APPKEY_CN "4d562c43fec3d427099353f3afd8d720"

#define STR_SITE_US "US"
#define STR_APPID_US "6f3dd7e7"
#define STR_APPKEY_US "fb889a64c3413f7e51bc58b9f7a008c8"

#define STR_SITE_JP "JP"
#define STR_APPID_JP "3dbfee9e"
#define STR_APPKEY_JP "b399f8c6c537e7ab3c02fd8b9e168a37"

#define STR_SITE_SG "SG"
#define STR_APPID_SG "ab467af6"
#define STR_APPKEY_SG "53984bbbbdb983be22a0b0b37e40f749"

// server extension
#define STR_EXTENSION_DO_ACTION_RESPONSE "doActionResponse"

// Thing onboarding
#define STR_DEVICE_TYPE "LED"
#define STR_PASSWORD "123456"

#define LIGHT_TYPE_SIZE 16
#define LIGHT_JSON_OBJECT_SIZE 512

// remote control
#define STR_LED_BUCKET_CONTROL "LEDControl"          // thing scope
#define STR_LED_BUCKET_RESPONSE "LEDControlResponse" // thing scope
#define STR_LED_BUCKET_REPORT "LEDReport" // thing scope
#define STR_LED_MEDIA_TYPE "LED"

// firmware upgrade
#define STR_JSON_TYPE_FIRMWAREUPGRADE "firmwareUpgrade"
#define STR_JSON_FIRMWARE_URL "\"firmwareUrl\":"
#define STR_JSON_VERSION_NAME "\"versionName\":"
#define STR_JSON_FIRMWARE_BUCKET_PREFIX "FirmwareUpgrade_"

#define STR_JSON_TYPE "\"type\":"

#define STR_JSON_TYPE_COMMAND "command"
#define STR_JSON_LIGHT_STATE "\"state\":"
#define STR_JSON_LIGHT_COLOR "\"color\":"
#define STR_JSON_LIGHT_BRIGHTNESS "\"brightness\":"
#define STR_JSON_LIGHT_CT "\"CT\":"
#define STR_JSON_LIGHT_MODE "\"mode\":"
#define LIGHT_MODE_COLOR_ACTIVE 0
#define LIGHT_MODE_CT_ACTIVE 1

#define STR_JSON_TYPE_QUERYSTATUS "queryStatus"

#define STR_JSON_TYPE_UPDATEPWD "updatePwd"
#define STR_JSON_NEW_PWD "\"newPwd\":"
#define STR_JSON_PASSWORD "\"password\":"

#define STR_JSON_TYPE_FACTORY_RESET "factoryReset"
#define STR_JSON_FACTORY_RESET "\"factoryReset\":"

#define STR_JSON_REQUESTID "\"requestID\":"
#define STR_JSON_THINGID "\"thingID\":"

#define STR_JSON_FIRMWARE_VERSION "\"firmwareVersion\":"

#define STR_JSON_IP_ADDRESS "\"ipAddress\":"

#define STR_JSON_TRUE "true"
#define STR_JSON_FALSE "false"

int light_init(void);
int light_updateStatus(light_struct light);

#endif
