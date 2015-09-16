#include <string.h>
#include "wm_include.h"
#if DEMO_KII
#include "kii.h"
#include "light.h"
#include "light_if.h"


static char mVendorID[KII_DEVICE_VENDOR_ID + 1];
static char mModelName[LIGHT_MODEL_NAME_SIZE + 1];
static int light_buildJson(char* jsonBuf, light_struct light)
{
	// state
	strcpy(jsonBuf + strlen(jsonBuf), STR_JSON_LIGHT_STATE);
	sprintf(jsonBuf + strlen(jsonBuf), "%d", light.state);
	strcat(jsonBuf, ",");

	// color
	strcat(jsonBuf, STR_JSON_LIGHT_COLOR);
	strcat(jsonBuf, "0x");
	strcat(jsonBuf, "ff");                                      // alpha
	sprintf(jsonBuf + strlen(jsonBuf), "%02x", light.color[0]); // R
	sprintf(jsonBuf + strlen(jsonBuf), "%02x", light.color[1]); // G
	sprintf(jsonBuf + strlen(jsonBuf), "%02x", light.color[2]); // B
	strcat(jsonBuf, ",");

	// brightness
	strcat(jsonBuf, STR_JSON_LIGHT_BRIGHTNESS);
	sprintf(jsonBuf + strlen(jsonBuf), "%d", light.brightness);
	strcat(jsonBuf, ",");

	// CT
	strcat(jsonBuf, STR_JSON_LIGHT_CT);
	sprintf(jsonBuf + strlen(jsonBuf), "%d", light.ct);
	strcat(jsonBuf, ",");

	// mode
	strcat(jsonBuf, STR_JSON_LIGHT_MODE);
	if((light.effectiveField & LIGHT_EFFECTIVE_FIELD_COLOR) > 0)
	{
		sprintf(jsonBuf + strlen(jsonBuf), "%d", LIGHT_MODE_COLOR_ACTIVE);
	}
	else if((light.effectiveField & LIGHT_EFFECTIVE_FIELD_CT) > 0)
	{
		sprintf(jsonBuf + strlen(jsonBuf), "%d", LIGHT_MODE_CT_ACTIVE);
	}

	return 0;
}

static void light_status_event_callback(light_struct *light)
{
	char objectID[KII_OBJECTID_SIZE + 1];
	char *jsonObject=NULL;//[LIGHT_JSON_OBJECT_SIZE + 1];
	lightIf_status(light); // get light whole status
	jsonObject = tls_mem_alloc(LIGHT_JSON_OBJECT_SIZE + 1);
	if(jsonObject == NULL)
		return;
	memset(jsonObject, 0, LIGHT_JSON_OBJECT_SIZE + 1);
	memset(objectID, 0, KII_OBJECTID_SIZE + 1);
	strcpy(jsonObject, "{");
	light_buildJson(jsonObject + strlen(jsonObject), *light);
	strcat(jsonObject, "}");
	printf("action response json:\r\n%s\r\n", jsonObject);
	if(kiiObj_create(KII_THING_SCOPE, STR_LED_BUCKET_REPORT, jsonObject, "report", objectID) < 0)
	{
		printf("do action response failed\r\n");
	}
	else
	{
		// printf("do action response success\r\n");
	}
	if(jsonObject)
		tls_mem_free(jsonObject);
	
}
static int light_parseJson(char* jsonBuf, light_struct* light)
{
	char* p;
	unsigned long value;

	memset(light, 0, sizeof(light_struct));
	// state
	p = strstr(jsonBuf, STR_JSON_LIGHT_STATE);
	if(p != NULL)
	{
		p += strlen(STR_JSON_LIGHT_STATE);
		value = strtoul(p, 0, 0);
		light->state = (unsigned char)value;
		light->effectiveField |= LIGHT_EFFECTIVE_FIELD_STATE;
	}

	// color, ignore alpha value if exist
	p = strstr(jsonBuf, STR_JSON_LIGHT_COLOR);
	if(p != NULL)
	{
		p += strlen(STR_JSON_LIGHT_COLOR);
		value = strtoul(p, 0, 0);
		light->color[0] = (unsigned char)(value >> 16); // R
		light->color[1] = (unsigned char)(value >> 8);  // G
		light->color[2] = (unsigned char)value;         // B
		light->effectiveField |= LIGHT_EFFECTIVE_FIELD_COLOR;
	}

	// brightness
	p = strstr(jsonBuf, STR_JSON_LIGHT_BRIGHTNESS);
	if(p != NULL)
	{
		p += strlen(STR_JSON_LIGHT_BRIGHTNESS);
		value = strtoul(p, 0, 0);
		light->brightness = (unsigned char)value;
		light->effectiveField |= LIGHT_EFFECTIVE_FIELD_BRIGHTESS;
	}

	// CT
	p = strstr(jsonBuf, STR_JSON_LIGHT_CT);
	if(p != NULL)
	{
		p += strlen(STR_JSON_LIGHT_CT);
		value = strtoul(p, 0, 0);
		light->ct = (unsigned char)value;
		light->effectiveField |= LIGHT_EFFECTIVE_FIELD_CT;
	}

	// mode
	p = strstr(jsonBuf, STR_JSON_LIGHT_MODE);
	if(p != NULL)
	{
		p += strlen(STR_JSON_LIGHT_MODE);
		value = strtoul(p, 0, 0);
		if(value == LIGHT_MODE_COLOR_ACTIVE)
		{
			light->effectiveField &= (~LIGHT_EFFECTIVE_FIELD_CT);
		}
		else if(value == LIGHT_MODE_CT_ACTIVE)
		{
			light->effectiveField &= (~LIGHT_EFFECTIVE_FIELD_COLOR);
		}
	}
	return 0;
}

int light_updateStatus(light_struct light)
{
	char jsonObject[512];

	memset(jsonObject, 0, sizeof(jsonObject));
	strcpy(jsonObject, "{");
	light_buildJson(jsonObject + strlen(jsonObject), light);
	strcat(jsonObject, ",");
	strcat(jsonObject, STR_JSON_THINGID);
	strcat(jsonObject, "\"");
	strcat(jsonObject, mVendorID);
	strcat(jsonObject, "\"");
	strcat(jsonObject, "}");

	printf("action response json:\r\n%s\r\n", jsonObject);
	if(kiiExt_extension(STR_EXTENSION_DO_ACTION_RESPONSE, jsonObject) < 0)
	{
		printf("do action response failed\r\n");
		return -1;
	}
	else
	{
		return 0;
	}
}

void light_parseLedControl(char* bucketName, char* objectID)
{
	char *jsonObject = NULL;//[LIGHT_JSON_OBJECT_SIZE + 1];
	char type[LIGHT_TYPE_SIZE + 1];
	char pwd[LIGHT_PASSWORD_SIZE + 1];
	char *bodyUrl = NULL;//[LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1];
	char *bodyUrlFinal = NULL;//[LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1];
	char versionName[LIGHT_VERSION_NAME_SIZE + 1];
	char* p1;
	char* p2;
	int i;
	int j;
	light_struct light;

	jsonObject = tls_mem_alloc(LIGHT_JSON_OBJECT_SIZE + 1);
	if(jsonObject == NULL)
		goto out;
	// retrieve object
	memset(jsonObject, 0, LIGHT_JSON_OBJECT_SIZE + 1);
	if(kiiObj_retrieve(KII_THING_SCOPE, bucketName, objectID, jsonObject, LIGHT_JSON_OBJECT_SIZE) < 0)
	{
		printf("Retrieve object failed, objectID:\"%s\"\r\n", objectID);
		goto out;
	}

	// get type
	memset(type, 0, sizeof(type));
	p1 = strstr(jsonObject, STR_JSON_TYPE);
	if(p1 != NULL)
	{
		p1 += strlen(STR_JSON_TYPE);
		p1 = strstr(p1, "\"");
		p1++;
		p2 = strstr(p1, "\"");
		memcpy(type, p1, p2 - p1);
	}
	else
	{
		printf("get type failed\r\n");
		goto out;
	}

	if(strcmp(type, STR_JSON_TYPE_COMMAND) == 0)
	{
		if(light_parseJson(jsonObject, &light) == 0)
		{
			lightIf_control(light);
		}
		else
		{
			printf("Invalid light control command\r\n");
		}
	}
	else if(strcmp(type, STR_JSON_TYPE_QUERYSTATUS) == 0)
	{
		light_status_event_callback(&light);
	}
	else if(strcmp(type, STR_JSON_TYPE_UPDATEPWD) == 0)
	{
		// get password
		memset(pwd, 0, sizeof(pwd));
		p1 = strstr(jsonObject, STR_JSON_NEW_PWD);
		if(p1 != NULL)
		{
			p1 += strlen(STR_JSON_NEW_PWD);
			p1 = strstr(p1, "\"");
			p1++;
			p2 = strstr(p1, "\"");
			memcpy(pwd, p1, p2 - p1);
			lightIf_updatePassword(pwd);
			// response to cloud
			memset(jsonObject, 0, LIGHT_JSON_OBJECT_SIZE + 1);
			strcpy(jsonObject, "{");
			// add adminPwd field
			strcat(jsonObject, STR_JSON_PASSWORD);
			strcat(jsonObject, "\"");
			strcat(jsonObject, pwd);
			strcat(jsonObject, "\"");
			// add requestID field
			strcat(jsonObject, ",");
			strcat(jsonObject, STR_JSON_REQUESTID);
			strcat(jsonObject, "\"");
			strcat(jsonObject, objectID);
			strcat(jsonObject, "\"");
			// add thingID field
			strcat(jsonObject, ",");
			strcat(jsonObject, STR_JSON_THINGID);
			strcat(jsonObject, "\"");
			strcat(jsonObject, mVendorID);
			strcat(jsonObject, "\"");
			strcat(jsonObject, "}");
			printf("action response json:\r\n%s\r\n", jsonObject);
			if(kiiExt_extension(STR_EXTENSION_DO_ACTION_RESPONSE, jsonObject) < 0)
			{
				printf("do action response failed\r\n");
			}
			else
			{
				// printf("do action response success\r\n");
			}
		}
		else
		{
			printf("get password failed\r\n");
		}
	}
	else if(strcmp(type, STR_JSON_TYPE_FACTORY_RESET) == 0)
	{
		memset(jsonObject, 0, LIGHT_JSON_OBJECT_SIZE + 1);
		strcpy(jsonObject, "{");
		strcat(jsonObject, STR_JSON_FACTORY_RESET);
		strcat(jsonObject, STR_JSON_TRUE);
		// add requestID field
		strcat(jsonObject, ",");
		strcat(jsonObject, STR_JSON_REQUESTID);
		strcat(jsonObject, "\"");
		strcat(jsonObject, objectID);
		strcat(jsonObject, "\"");
		// add thingID field
		strcat(jsonObject, ",");
		strcat(jsonObject, STR_JSON_THINGID);
		strcat(jsonObject, "\"");
		strcat(jsonObject, mVendorID);
		strcat(jsonObject, "\"");
		strcat(jsonObject, "}");
		printf("action response json:\r\n%s\r\n", jsonObject);
		if(kiiExt_extension(STR_EXTENSION_DO_ACTION_RESPONSE, jsonObject) < 0)
		{
			printf("do action response failed\r\n");
		}
		else
		{
			printf("factory reset...\r\n");
			lightIf_factoryReset();
		}
	}
	else if(strcmp(type, STR_JSON_TYPE_FIRMWAREUPGRADE) == 0)
	{
		// get  version name
		memset(versionName, 0, sizeof(versionName));
		p1 = strstr(jsonObject, STR_JSON_VERSION_NAME);
		if(p1 != NULL)
		{
			p1 += strlen(STR_JSON_VERSION_NAME);
			p1 = strstr(p1, "\"");
			p1++;
			p2 = strstr(p1, "\"");
			memcpy(versionName, p1, p2 - p1);
		}
		else
		{
			printf("get version name failed\r\n");
			goto out;
		}
		bodyUrl = tls_mem_alloc(LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
		if(bodyUrl == NULL)
			goto out;
		// get body url
		memset(bodyUrl, 0, LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
		p1 = strstr(jsonObject, STR_JSON_FIRMWARE_URL);
		if(p1 != NULL)
		{
			p1 += strlen(STR_JSON_FIRMWARE_URL);
			p1 = strstr(p1, "\"");
			p1++;
			p2 = strstr(p1, "\"");
			memcpy(bodyUrl, p1, p2 - p1);
		}
		else
		{
			printf("get body url failed\r\n");
			goto out;
		}
		bodyUrlFinal = tls_mem_alloc(LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
		if(bodyUrlFinal == NULL)
			goto out;
		memset(bodyUrlFinal, 0, LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
		strcpy(bodyUrlFinal, "http");
		j = strlen(bodyUrlFinal);
		for(i = 5; i < strlen(bodyUrl); i++)
		{
			if(bodyUrl[i] != '\\')
			{
				bodyUrlFinal[j++] = bodyUrl[i];
			}
		}
		//		printf("bodyUrl:%s\r\n", bodyUrl);
		printf("bodyUrlFinal:%s\r\n", bodyUrlFinal);
		printf("versionName:%s\r\n", versionName);
		lightIf_firmwareUpgrade(bodyUrlFinal, versionName);
	}
	else
	{
		printf("invalid type:"
		       "%s"
		       "\r\n",
		       type);
	}
out:
	if(jsonObject)
		tls_mem_free(jsonObject);
	if(bodyUrl)
		tls_mem_free(bodyUrl);
	if(bodyUrlFinal)
		tls_mem_free(bodyUrlFinal);
}

void light_parseFirmwareUpgrade(char* bucketName, char* objectID)
{
	char *jsonObject=NULL;//[LIGHT_JSON_OBJECT_SIZE + 1];
	// char pointerObjectID[KII_OBJECTID_SIZE+1];
	// char pointerBucketName[KII_BUCKET_NAME_SIZE+1];
	char *bodyUrl=NULL;//[LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1];
	char *bodyUrlFinal=NULL;//[LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1];
	char versionName[LIGHT_VERSION_NAME_SIZE + 1];
	char* p1;
	char* p2;
	int i;
	int j;

	jsonObject = tls_mem_alloc(LIGHT_JSON_OBJECT_SIZE + 1);
	if(jsonObject == NULL)
		goto out;
	// retrieve object
	memset(jsonObject, 0, LIGHT_JSON_OBJECT_SIZE + 1);
	if(kiiObj_retrieve(KII_APP_SCOPE, bucketName, objectID, jsonObject, LIGHT_JSON_OBJECT_SIZE) < 0)
	{
		printf("Retrieve object failed, objectID:\"%s\"\r\n", objectID);
		goto out;
	}
	// printf("jsonObject:%s\r\n", jsonObject);
	// get  version name
	memset(versionName, 0, sizeof(versionName));
	p1 = strstr(jsonObject, STR_JSON_VERSION_NAME);
	if(p1 != NULL)
	{
		p1 += strlen(STR_JSON_VERSION_NAME);
		p1 = strstr(p1, "\"");
		p1++;
		p2 = strstr(p1, "\"");
		memcpy(versionName, p1, p2 - p1);
	}
	else
	{
		printf("get version name failed\r\n");
		goto out;
	}
	bodyUrl = tls_mem_alloc(LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
	if(bodyUrl == NULL)
		goto out;
	// get body url
	memset(bodyUrl, 0, LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
	p1 = strstr(jsonObject, STR_JSON_FIRMWARE_URL);
	if(p1 != NULL)
	{
		p1 += strlen(STR_JSON_FIRMWARE_URL);
		p1 = strstr(p1, "\"");
		p1++;
		p2 = strstr(p1, "\"");
		memcpy(bodyUrl, p1, p2 - p1);
	}
	else
	{
		printf("get body url failed\r\n");
		goto out;
	}
	bodyUrlFinal = tls_mem_alloc(LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
	if(bodyUrlFinal == NULL)
		goto out;
	memset(bodyUrlFinal, 0, LIGHT_FIRMWARE_UPGRADE_URL_SIZE + 1);
	strcpy(bodyUrlFinal, "http");
	j = strlen(bodyUrlFinal);
	for(i = 5; i < strlen(bodyUrl); i++)
	{
		if(bodyUrl[i] != '\\')
		{
			bodyUrlFinal[j++] = bodyUrl[i];
		}
	}
	// printf("firmware upgrade ...\r\n");
	// printf("bodyUrl:%s\r\n", bodyUrl);
	printf("bodyUrlFinal:%s\r\n", bodyUrlFinal);
	printf("versionName:%s\r\n", versionName);
	lightIf_firmwareUpgrade(bodyUrlFinal, versionName);
out:
	if(jsonObject)
		tls_mem_free(jsonObject);
	if(bodyUrl)
		tls_mem_free(bodyUrl);
	if(bodyUrlFinal)
		tls_mem_free(bodyUrlFinal);
}

void light_callback(char* jsonBuf, int rcvdCounter)
{
	char objectID[KII_OBJECTID_SIZE + 1];
	char bucketName[KII_BUCKET_NAME_SIZE + 1];
	char bucketModel[KII_BUCKET_NAME_SIZE + 1];
	char* p1;
	char* p2;

	// printf("Push callback: jsonbuf:\r\n%s\r\n", jsonBuf);
	p1 = strstr(jsonBuf, "\"objectID\":\"");
	if(p1 != NULL)
	{
		p1 += 12;
		p2 = strstr(p1, "\"");
		memset(objectID, 0, sizeof(objectID));
		memcpy(objectID, p1, p2 - p1);
	}
	else
	{
		printf("get objectID failed\r\n");
		return;
	}

	p1 = strstr(jsonBuf, "\"bucketID\":\"");
	if(p1 != NULL)
	{
		p1 += 12;
		p2 = strstr(p1, "\"");
		memset(bucketName, 0, sizeof(bucketName));
		memcpy(bucketName, p1, p2 - p1);
	}
	else
	{
		printf("get bucketID failed\r\n");
		return;
	}

	// printf("bucketID:%s\r\n", bucketName);
	// printf("objectID:%s\r\n", objectID);
	if(strcmp(bucketName, STR_LED_BUCKET_CONTROL) == 0)
	{
		light_parseLedControl(bucketName, objectID);
	}
	else
	{
		memset(bucketModel, 0, sizeof(bucketModel));
		strcpy(bucketModel, STR_JSON_FIRMWARE_BUCKET_PREFIX);
		strcat(bucketModel, mModelName);
		if(strcmp(bucketName, bucketModel) == 0)
		{
			light_parseFirmwareUpgrade(bucketName, objectID);
		}
		else
		{
			printf("Invalid bucket name(%s)\r\n", bucketName);
		}
	}
}

int light_initPush(void)
{
	char bucketModel[KII_BUCKET_NAME_SIZE + 1];

	memset(bucketModel, 0, sizeof(bucketModel));
	strcpy(bucketModel, STR_JSON_FIRMWARE_BUCKET_PREFIX);
	strcat(bucketModel, mModelName);

	if(kiiPush_subscribeBucket(KII_APP_SCOPE, bucketModel) < 0)
	{
		return -1;
	}
	if(kiiPush_subscribeBucket(KII_THING_SCOPE, STR_LED_BUCKET_CONTROL) < 0)
	{
		return -1;
	}

	if(KiiPush_init(DEMO_KII_PUSH_RECV_MSG_TASK_PRIO, DEMO_KII_PUSH_PINGREQ_TASK_PRIO, light_callback) < 0)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

int light_onBoarding(void)
{
	if(kii_init(STR_SITE_US, STR_APPID_US, STR_APPKEY_US) == 0)
	{
		if(kiiDev_getToken(mVendorID, STR_PASSWORD) != 0)
		{
			if(kiiDev_register(mVendorID, STR_DEVICE_TYPE, STR_PASSWORD) == 0)
				return 0;
		}
		else{
			return 0;
		}
	}
/*	
	if(kii_init(STR_SITE_US, STR_APPID_US, STR_APPKEY_US) == 0)
	{
		if(kiiDev_getToken(mVendorID, STR_PASSWORD) == 0)
		{
			return 0;
		}
	}
	if(kii_init(STR_SITE_JP, STR_APPID_JP, STR_APPKEY_JP) == 0)
	{
		if(kiiDev_getToken(mVendorID, STR_PASSWORD) == 0)
		{
			return 0;
		}
	}
	if(kii_init(STR_SITE_SG, STR_APPID_SG, STR_APPKEY_SG) == 0)
	{
		if(kiiDev_getToken(mVendorID, STR_PASSWORD) == 0)
		{
			return 0;
		}
	}
*/	
	return -1;
}

int light_updateBootupStatus(void)
{
	char jsonObject[LIGHT_JSON_OBJECT_SIZE + 1];
	char pwd[LIGHT_PASSWORD_SIZE + 1];
	char firmwareVersion[LIGHT_VERSION_NAME_SIZE + 1];
	char ipAddress[LIGHT_IP_ADDRESS_SIZE + 1];
	light_struct light;

	memset(jsonObject, 0, sizeof(jsonObject));
	// add light status
	lightIf_status(&light);
	strcpy(jsonObject, "{");
	light_buildJson(jsonObject + strlen(jsonObject), light);
	// add firmware version field
	strcat(jsonObject, ",");
	strcat(jsonObject, STR_JSON_FIRMWARE_VERSION);
	memset(firmwareVersion, 0, sizeof(firmwareVersion));
	lightIf_getFirmwareVersion(firmwareVersion);
	strcat(jsonObject, "\"");
	strcat(jsonObject, firmwareVersion);
	strcat(jsonObject, "\"");
	// add password field after factory reset
	memset(pwd, 0, sizeof(pwd));
	lightIf_getPassword(pwd);
	if(strlen(pwd) > 0)
	{
		strcat(jsonObject, ",");
		strcat(jsonObject, STR_JSON_PASSWORD);
		strcat(jsonObject, "\"");
		strcat(jsonObject, pwd);
		strcat(jsonObject, "\"");
	}
	// add ip address field
	strcat(jsonObject, ",");
	strcat(jsonObject, STR_JSON_IP_ADDRESS);
	memset(ipAddress, 0, sizeof(ipAddress));
	// lightIf_getIPAddress(ipAddress);
	if(kiiDev_getIPAddress(ipAddress) < 0)
	{
		strcpy(ipAddress, "255.255.255.255");
	}
	strcat(jsonObject, "\"");
	strcat(jsonObject, ipAddress);
	strcat(jsonObject, "\"");
	// add thingID field
	strcat(jsonObject, ",");
	strcat(jsonObject, STR_JSON_THINGID);
	strcat(jsonObject, "\"");
	strcat(jsonObject, mVendorID);
	strcat(jsonObject, "\"");

	strcat(jsonObject, "}");
	printf("action response json:\r\n%s\r\n", jsonObject);
	if(kiiExt_extension(STR_EXTENSION_DO_ACTION_RESPONSE, jsonObject) < 0)
	{
		printf("do action response failed\r\n");
		return -1;
	}
	else
	{
		// printf("do action response success\r\n");
		if(strlen(pwd) > 0)
		{
			memset(pwd, 0, sizeof(pwd));
			lightIf_updatePassword(pwd);
		}
		return 0;
	}
}
int light_init(void)
{
	memset(mVendorID, 0, sizeof(mVendorID));
	if(lightIf_getMacAddr(mVendorID) < 0)
	{
		printf("Get mac address failed\r\n");
		return -1;
	}
	printf("vendorID:%s\r\n", mVendorID);

	memset(mModelName, 0, sizeof(mModelName));
	if(lightIf_getIModelName(mModelName) < 0)
	{
		printf("Get model name failed\r\n");
		return -1;
	}
	printf("Model name:%s\r\n", mModelName);

	if(light_onBoarding() != 0)
	{
		printf("Light onbording failed\r\n");
		return -1;
	}
	else
	{
		printf("light onboarding success\r\n");
	}
/*
	if(light_updateBootupStatus() < 0)
	{
		printf("Update bootup status failed\r\n");
		return -1;
	}
	else
	{
		printf("Update bootup status success\r\n");
	}
*/
	if(light_initPush() < 0)
	{
		printf("Initialize push failed\r\n");
		return -1;
	}
	else
	{
		printf("Initialize push success\r\n");
	}
	lightIf_add_status_event(light_status_event_callback);
	return 0;
}
#endif

