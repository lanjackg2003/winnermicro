#include "wm_config.h"

#if TLS_CONFIG_CLOUD_JD
#include <string.h>
#include "lwip/inet.h"
#include "utils.h"
#include "wm_task.h"
#include "wm_flash.h"
#include "wm_debug.h"
#include "wm_cloud.h"
#include "wm_cloud_server.h"
#include "cJSON.h"

#define PARAM_ADDR  0x000EEE00
#define MAGIC_HEADER 0x61198515
#define MAX_STREAM_COUNT  20
extern unsigned long HTTPWrapperGetHostByName(char *name,unsigned long *address);

 typedef struct _DEVICE_PARAM
{
    CHAR                *pParam;
    UINT32              nLength;
} DEVICE_PARAM;

typedef struct _JD_PARAM
{
	DEVICE_PARAM product_uuid;
	DEVICE_PARAM feed_id;
	DEVICE_PARAM access_key;
	DEVICE_PARAM server;
}JD_PARAM;

cloud_callback jd_cloud_callback = NULL;
static CloudServerSockArray * cloudSockArray = NULL;
static u8 jd_cloud_initialized = 0;
static JD_PARAM jd_param;
extern u8 server_state;
static int write_param(u32* addr, DEVICE_PARAM *p)
{
	int ret = 0;
	ret = tls_fls_write(*addr, (u8 *)&p->nLength, sizeof(UINT32));
	if(ret)
		return ret;
	TLS_DBGPRT_INFO("write p->nLength : %d\n", p->nLength);
	*addr += sizeof(UINT32);
	if(p->nLength > 0)
	{
		ret = tls_fls_write(*addr, (u8 *)p->pParam, p->nLength);
		if(ret)
			return ret;
		TLS_DBGPRT_INFO("write p->pParam : %s\n", p->pParam);
		*addr += p->nLength;
	}
	return 0;
}

static int write_jd_param(JD_PARAM * p)
{
	int ret = 0;
	u32 addr = PARAM_ADDR;
	u32 magic = MAGIC_HEADER;
	ret = tls_fls_write(addr, (u8 *)&magic, 4);
	if(ret)
	{
		TLS_DBGPRT_INFO("write magic error: %d\n", ret);
		return ret;
	}
	addr += 4;
	if((ret = write_param(&addr, &p->product_uuid)) || (ret = write_param(&addr, &p->feed_id))
		|| (ret = write_param(&addr, &p->access_key)) || (ret = write_param(&addr, &p->server)))
	{
		TLS_DBGPRT_INFO("write param error: %d\n", ret);
		return ret;
	}
	return 0;
}

static int read_param(u32* addr, DEVICE_PARAM *p)
{
	tls_fls_read(*addr, (u8 *)&p->nLength, sizeof(UINT32));
	*addr += sizeof(UINT32);
	if(p->nLength > 0)
	{
		TLS_DBGPRT_INFO(" p->nLength = %d \n", p->nLength);
		p->pParam = tls_mem_alloc(p->nLength + 1);
		if(p->pParam == NULL)
		{
			*addr += p->nLength;
			return -1;
		}
		memset(p->pParam, 0, p->nLength + 1);
		tls_fls_read(*addr, (u8 *)p->pParam, p->nLength);
		*addr += p->nLength;
		TLS_DBGPRT_INFO(" p->pParam = %s \n", p->pParam);
	}
	return 0;
}

static int read_jd_param(JD_PARAM * p)
{
	u32 addr = PARAM_ADDR;
	u32 magic = 0;
	tls_fls_read(addr, (u8 *)&magic, 4);
	if(magic != MAGIC_HEADER)
	{
		TLS_DBGPRT_INFO("read magic error: %x \n", magic);
		return 0;
	}
	addr += 4;
	if( read_param(&addr, &p->product_uuid) || read_param(&addr, &p->feed_id) ||
		read_param(&addr, &p->access_key) || read_param(&addr, &p->server))
	{
		return -1;
	}
	return 0;
}

static int free_param(DEVICE_PARAM *p)
{
	if(p == NULL)
		return 0;
	if(p->pParam && p->nLength > 0)
	{
		tls_mem_free(p->pParam);
		p->pParam = NULL;
		p->nLength = 0;
	}
	return 0;
}

static int free_jd_param(JD_PARAM * p)
{
	if(p == NULL)
		return 0;
	if( free_param(&p->product_uuid) || free_param(&p->feed_id) ||
		free_param(&p->access_key) || free_param(&p->server))
	{
		return -1;
	}
	//tls_mem_free(p);
	return 0;
}

extern u8 *wpa_supplicant_get_mac(void);
static void connect_jdcloud(void* arg)
{
	int ret = 0;
	ret = get_sockets(cloudSockArray);
	if(ret)
		tls_task_add_timeout(CLOUD_DATA_HANDLER_ID, 5000, connect_jdcloud, cloudSockArray);
	else
		tls_task_add_timeout(CLOUD_DATA_HANDLER_ID, 5000, send_heartbeat_data, cloudSockArray);
}
static void udp_recv_data_handler(CloudReadData *data)
{
	char * recvbuf = data->read_data;
	int len;
	char sum;
	char *p;
	int i;
	cJSON *json = NULL;
	char sendbuf[256] = {
		0xaa, 0x55, 0x00, 0x00, 
		0x18, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0d,
		0x02, 0x00, 0x00, 0x00,
		0x4f, 0x4b
	};
	int addrlen = sizeof(struct sockaddr);
	
	TLS_DBGPRT_INFO("%s\n", recvbuf + 19);

	if(recvbuf[13] == 1)
	{
		u8 * macaddr = wpa_supplicant_get_mac();
		char databuf[100] = {0};
		sprintf(databuf, "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"productuuid\":\"%s\",\"feedid\":\"%s\"}", 
			macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], 
			(jd_param.product_uuid.pParam == NULL ? "" : jd_param.product_uuid.pParam), 
			(jd_param.feed_id.pParam== NULL ? "" : jd_param.feed_id.pParam));
		TLS_DBGPRT_INFO("%s\n", databuf);
		//发现
		sendbuf[13] = 2;
		strcpy(sendbuf + 19, databuf);
		len = 6 + strlen(databuf);
		sum = 0;
		p = &sendbuf[13];
		for(i = 0; i < len; i++)
		{
			sum += *(p + i);
		}
		sendbuf[4] = len;
		sendbuf[12] = sum;
		socket_sendto(data->socket, sendbuf, len + 13, 0, (struct sockaddr *)&data->sin_recv, addrlen);
	}
	else
	if(recvbuf[13] == 3)
	{
		//写数据
		u8 configrated = 0;
		int code = 0;
		char * msg = NULL;
		char *databuf = NULL;
		cJSON * jsRet = NULL;
		cJSON * jsA = NULL;
		if(jd_param.feed_id.pParam != NULL)
		{
			configrated = 1;
		}
		json=cJSON_Parse(recvbuf + 19);
		if(json==NULL)
		{
			code = 1;
			msg = "parse json data failed.";
			TLS_DBGPRT_INFO("%s\n", msg);
			goto sendStart;
		}
		
		jsA = cJSON_GetObjectItem(json,"accesskey");
		if(jsA)
		{
			TLS_DBGPRT_INFO("accesskey=%s\n", jsA->valuestring);
			//jd_param.access_key.pParam = "b7a2d2b7098e83b89958d0851525d941";
			//jd_param.access_key.nLength = 32;
			if(jd_param.access_key.pParam != NULL)
				tls_mem_free(jd_param.access_key.pParam);
			jd_param.access_key.pParam = strdup(jsA->valuestring);
			jd_param.access_key.nLength = strlen(jsA->valuestring);
		}
		jsA = cJSON_GetObjectItem(json,"feedid");
		if(jsA)
		{
			TLS_DBGPRT_INFO("feedid=%s\n", jsA->valuestring);
			//jd_param.feed_id.pParam = "141812537884084412";
			//jd_param.feed_id.nLength = 18;
			if(jd_param.feed_id.pParam != NULL)
				tls_mem_free(jd_param.feed_id.pParam);
			jd_param.feed_id.pParam = strdup(jsA->valuestring);
			jd_param.feed_id.nLength = strlen(jsA->valuestring);
		}
		jsA = cJSON_GetObjectItem(json,"server");
		if(jsA)
		{
			int size = cJSON_GetArraySize(jsA);
			for(int i=0;i<size;i++)
			{
				cJSON * jsB = cJSON_GetArrayItem(jsA, i);
				if(jsB)
				{
					TLS_DBGPRT_INFO("server=%s\n", jsB->valuestring);
					if(jd_param.server.pParam != NULL)
						tls_mem_free(jd_param.server.pParam);
					jd_param.server.pParam = strdup(jsB->valuestring);
					jd_param.server.nLength = strlen(jsB->valuestring);
					break;
				}
			}
		}
		write_jd_param(&jd_param);
		
sendStart:
		jsRet = cJSON_CreateObject();
		if(jsRet)
		{
			cJSON_AddNumberToObject(jsRet,"code", code);
			if(code)
				cJSON_AddStringToObject(jsRet,"msg", msg);
			databuf = cJSON_PrintUnformatted(jsRet);
		}
		sendbuf[13] = 4;
		strcpy(sendbuf + 19, databuf);
		len = 6 + strlen(databuf);
		sum = 0;
		p = &sendbuf[13];
		for(i = 0; i < len; i++)
		{
			sum += *(p + i);
		}
		sendbuf[4] = len;
		sendbuf[12] = sum;
		socket_sendto(data->socket, sendbuf, len + 13, 0, (struct sockaddr *)&data->sin_recv, addrlen);
		if(databuf)
			tls_mem_free(databuf);
		if(jsRet)
			cJSON_Delete(jsRet);
		if(!code && !configrated)
		{
			tls_task_untimeout(CLOUD_DATA_HANDLER_ID, send_heartbeat_data, cloudSockArray);
			while(tls_task_callback_with_block(CLOUD_DATA_HANDLER_ID, (start_routine)connect_jdcloud, cloudSockArray, 0) != ERR_OK)
			{
				TLS_DBGPRT_INFO("tls_task_callback_with_block connect_jdcloud err\n");
				tls_os_time_delay(1);
			}
		}
	}
	if(data)
		free_read_data(data);
	if(json)
		cJSON_Delete(json);
}
static void control_req(cJSON * root)
{
	CloudData * data = NULL;
	cJSON * streams = NULL;
	cJSON * stream = NULL;
	cJSON * stream_id = NULL;
	cJSON * stream_val = NULL;
	cJSON * attribute = NULL;
	int stream_cnt = 0, i = 0, n = 0;
	char* names[MAX_STREAM_COUNT];
	char* values[MAX_STREAM_COUNT];
	data = tls_mem_alloc(sizeof(CloudData));
	if(data == NULL)
		goto end;
	memset(data, 0, sizeof(CloudData));
	data->opt = CONTROL_REQ;
	streams = cJSON_GetObjectItem(root, "control");
	if(streams == NULL)
		goto end;
	stream_cnt = cJSON_GetArraySize(streams);
	for(i=0; (i<stream_cnt && i<MAX_STREAM_COUNT); i++)
	{
		stream = cJSON_GetArrayItem(streams, i);
		stream_id = cJSON_GetObjectItem(stream, "stream_id");
		stream_val = cJSON_GetObjectItem(stream, "current_value");
		if(stream_id == NULL || stream_val == NULL)
			continue;
		names[n] = stream_id->valuestring;
		values[n++] = stream_val->valuestring;
	}
	if(n)
	{
		data->cnt = n;
		data->names = names;
		data->values = values;
	}
	else
		goto end;
	attribute = cJSON_GetObjectItem(root, "attribute");
	if(attribute)
	{
		data->arg = cJSON_Duplicate(attribute, 1);
	}
	if(jd_cloud_callback)
		jd_cloud_callback(data);
	if(data->opt == CONTROL_RESP)
	{
		tls_cloud_upload_data(data);
		if(data->control_resp)
			tls_mem_free(data->control_resp);
	}
end:
	if(data)
		tls_mem_free(data);
}

static void upload_resp(cJSON * root)
{
	CloudData * data = NULL;
	cJSON * resultJson = NULL;
	data = tls_mem_alloc(sizeof(CloudData));
	if(data == NULL)
		goto end;
	memset(data, 0, sizeof(CloudData));
	data->opt = UPLOAD_RESP;
	resultJson = cJSON_GetObjectItem(root, "result");
	if(resultJson == NULL)
		goto end;
	data->result = resultJson->valueint;
	if(jd_cloud_callback)
		jd_cloud_callback(data);
end:
	if(data)
		tls_mem_free(data);
}

static void snapshot_req(cJSON * root)
{
	CloudData * data = NULL;
	cJSON * attribute = NULL;
	int i = 0;
	data = tls_mem_alloc(sizeof(CloudData));
	if(data == NULL)
		goto end;
	memset(data, 0, sizeof(CloudData));
	data->opt = SNAPSHOT_REQ;
	attribute = cJSON_GetObjectItem(root, "attribute");
	if(attribute == NULL)
		goto end;
	data->arg = cJSON_Duplicate(attribute, 1);
	if(jd_cloud_callback)
		jd_cloud_callback(data);
	if(data->opt == SNAPSHOT_RESP)
	{
		tls_cloud_upload_data(data);
		if(data->cnt > 0)
		{
			for(i=0; i<data->cnt; i++)
			{
				if(data->names && data->names[i])
					tls_mem_free(data->names[i]);
				if(data->values && data->values[i])
					tls_mem_free(data->values[i]);
			}
			if(data->names)
				tls_mem_free(data->names);
			if(data->values)
				tls_mem_free(data->values);
		}
	}
end:
	if(data)
		tls_mem_free(data);
}
static void httpdecode(char *p, int isFind)	// isFind:是否找到连续换行
{
    int i = 0;
    int isLine = 0;
    isLine = !isFind;
    while(*(p + i))
    {
        if(isLine==0) //
        {
        	if(*(p+i)=='\n')
        	{
        		if(*(p+i+2)=='\n')
        		{
        			i+=1;
        			isLine = 1;
        		}
        	}
        	i++;
        	continue;
        }
        if ((*p = *(p + i)) == '%')
        {
            *p = *(p + i + 1) >= 'A' ? ((*(p + i + 1) & 0XDF) - 'A') + 10 : (*(p + i + 1) - '0');
            *p = (*p) * 16;
            *p += *(p + i + 2) >= 'A' ? ((*(p + i + 2) & 0XDF) - 'A') + 10 : (*(p + i + 2) - '0');
            i += 2;
        }
        else if (*(p + i) == '+')
        {
            *p = ' ';
        }
        p++;
    }
    *p = '\0';
}
static void tcp_recv_data_handler(CloudReadData *data)
{
	cJSON * root = NULL;
	cJSON * codeJson = NULL;
	int code = 0;
	httpdecode(data->read_data, 0);
	TLS_DBGPRT_INFO("tcp_recv_data_handler : %s\n", data->read_data);
	root = cJSON_Parse(data->read_data);
	if (!root) {
		TLS_DBGPRT_INFO("Error before: [%s]\n",cJSON_GetErrorPtr());
		goto end;
	}
	codeJson = cJSON_GetObjectItem(root, "code");
	code = codeJson->valueint;
	switch(code)
	{
		case 1001:
			break;
		case 1002:
			control_req(root);
			break;
		case 1003:
			upload_resp(root);
			break;
		case 1004:
			snapshot_req(root);
			break;
		default:
			break;
	}
end:
	free_read_data(data);
	if(root)
		cJSON_Delete(root);
}

void read_data_handler(void * the_data)
{
	CloudReadData *data = (CloudReadData *)the_data;
	TLS_DBGPRT_INFO("read_data_handler data->socket->sock_type=%d\n", data->socket->sock_type);
	if(data->socket->sock_type == 0)
		udp_recv_data_handler(data);
	else
		tcp_recv_data_handler(data);
}
static cJSON * create_object(int code)
{
	cJSON *jsRet = NULL;
	jsRet = cJSON_CreateObject();
	if(jsRet)
	{
		cJSON_AddNumberToObject(jsRet,"code", code);
		//cJSON_AddStringToObject(jsRet,"code", "101");
	}
	return jsRet;
}
static int add_device_object(cJSON * root)
{
	int ret = 0;
	//int feed_id = 0;
	cJSON *device = NULL;
	
	cJSON_AddItemToObject(root, "device", device=cJSON_CreateObject());
	if(device)
	{
		cJSON_AddStringToObject(device,"feed_id", jd_param.feed_id.pParam== NULL ? "" : jd_param.feed_id.pParam);
		cJSON_AddStringToObject(device,"access_key", jd_param.access_key.pParam== NULL ? "" : jd_param.access_key.pParam);
	}
	else
		ret = -1;
	return ret;
}
static int add_streams_object(cJSON * root, CloudData * data, u8 value)
{
	int ret = 0, i = 0;
	cJSON *streams = NULL;
	cJSON * stream = NULL;
	cJSON * datapoints = NULL;
	cJSON * datapoint = NULL;
	cJSON_AddItemToObject(root, "streams", streams=cJSON_CreateArray());
	if(streams)
	{
		for(i=0; i<data->cnt; i++)
		{
			cJSON_AddItemToArray(streams, stream=cJSON_CreateObject());
			if(stream == NULL)
				break;
			cJSON_AddStringToObject(stream, "stream_id", data->names[i]);
			cJSON_AddItemToObject(stream, "datapoints", datapoints=cJSON_CreateArray());
			if(datapoints == NULL)
				break;
			cJSON_AddItemToArray(datapoints, datapoint=cJSON_CreateObject());
			cJSON_AddStringToObject(datapoint, value ? "value" : "current_value", data->values[i]);
		}
	}
	else
		ret = -1;
	return ret;
}

static int add_attribute_object(cJSON * root, CloudData * data)
{
	int ret = 0;
	cJSON *attribute = (cJSON *)data->arg;
	if(attribute)
		cJSON_AddItemToObject(root, "attribute", attribute);
	data->arg = NULL;
	return ret;
}
static int add_result_object(cJSON * root, CloudData * data)
{
	int ret = 0;
	//if(data->result)
		cJSON_AddNumberToObject(root, "result", data->result);
	return ret;
}
static int add_control_resp_object(cJSON * root, CloudData * data)
{
	int ret = 0;
	if(data->control_resp)
		cJSON_AddStringToObject(root, "control_resp", data->control_resp);
	return ret;
}
void send_heartbeat_data(void * arg)
{
	int ret = 0;
	cJSON *jsRet = NULL;
	char * databuf = NULL;
	CloudServerSockArray *cloudSock = (CloudServerSockArray *)arg;
	if(cloudSock->socket2->socket_num == INVALID_SOCKET)
		return;
	jsRet = create_object(101);
	if(jsRet)
	{
		ret = add_device_object(jsRet);
		if(!ret)
			databuf = cJSON_PrintUnformatted(jsRet);
	}
	ret = 0;
	if(databuf)
	{
		ret = socket_sendto(cloudSock->socket2, databuf, strlen(databuf), 0, NULL, MSG_DONTWAIT);
		ret = socket_sendto(cloudSock->socket2, "\n", 1, 0, NULL, MSG_DONTWAIT);
	}
	if(ret >= 0)
		tls_task_add_timeout(CLOUD_DATA_HANDLER_ID, 60000, send_heartbeat_data, cloudSock);
	//else
		//sock_close(cloudSock->socket2);
	if(databuf)
		tls_mem_free(databuf);
	if(jsRet)
		cJSON_Delete(jsRet);
}
int get_cloud_sockets(CloudServerSockArray *cloudSock)
{
	int ret = 0;
	struct sockaddr_in sin;
	unsigned short local_port;
	local_port = 80;
	CHAR    *pDstStart;
	char server[128] = {0};
	char port[11] = {0};
	unsigned long serverAddr = 0;
	cloudSockArray = cloudSock;
#if 1	
	if(cloudSock->socket1 == NULL || cloudSock->socket1->sock_addr == NULL)
	{
		memset(&sin, 0, sizeof(struct sockaddr));
		// ??socket
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		sin.sin_family = AF_INET;
		sin.sin_port = htons(local_port);
		if(cloudSock->socket1 == NULL)
			cloudSock->socket1 = tls_mem_alloc(sizeof(SOCKET));
		if(cloudSock->socket1 == NULL)
		{
			ret = -1;
			goto end;
		}
		memset(cloudSock->socket1, 0, sizeof(SOCKET));
		cloudSock->socket1->sock_addr = tls_mem_alloc(sizeof(struct sockaddr));
		if(cloudSock->socket1->sock_addr == NULL)
		{
			ret = -1;
			goto end;
		}
		memcpy(cloudSock->socket1->sock_addr, &sin, sizeof(struct sockaddr));
		cloudSock->socket1->sock_type = 0;//UDP
		cloudSock->socket1->socket_num = -1;
	}
#endif
	if(cloudSock->socket2 == NULL || cloudSock->socket2->sock_addr == NULL)
	{
		memset(&sin, 0, sizeof(struct sockaddr));
		if(jd_param.server.pParam == NULL)
			goto end;
		pDstStart = strstr(jd_param.server.pParam, ":");
		memcpy(server, jd_param.server.pParam, pDstStart - jd_param.server.pParam);
		memcpy(port, pDstStart + 1, strlen(jd_param.server.pParam) - (pDstStart - jd_param.server.pParam + 1));
		TLS_DBGPRT_INFO("ipAddr = %s, port = %s \n", server, port);
		local_port = (unsigned short)atol(port);
#if TLS_CONFIG_HTTP_CLIENT_SECURE
		HTTPWrapperGetHostByName(server, &serverAddr);
#endif
		sin.sin_addr.s_addr = serverAddr;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(local_port);
		if(cloudSock->socket2 == NULL)
			cloudSock->socket2 = tls_mem_alloc(sizeof(SOCKET));
		if(cloudSock->socket2 == NULL)
		{
			ret = -1;
			goto end;
		}
		memset(cloudSock->socket2, 0, sizeof(SOCKET));
		cloudSock->socket2->sock_addr = tls_mem_alloc(sizeof(struct sockaddr));
		if(cloudSock->socket2->sock_addr == NULL)
		{
			ret = -1;
			goto end;
		}
		memcpy(cloudSock->socket2->sock_addr, &sin, sizeof(struct sockaddr));
		cloudSock->socket2->sock_type = SOCKET_TCP|SOCKET_CLINET|SOCKET_SSL;//TCP
		cloudSock->socket2->socket_num = -1;
	}
end:
	//free_jd_param(&param);
	return ret;
}

static void send_upload_data(void * arg)
{
	char * databuf = (char *)arg;
	if(cloudSockArray && cloudSockArray->socket2)
	{
		socket_sendto(cloudSockArray->socket2, databuf, strlen(databuf), 0, NULL, MSG_DONTWAIT);
		socket_sendto(cloudSockArray->socket2, "\n", 1, 0, NULL, MSG_DONTWAIT);
	}
	tls_mem_free(databuf);
}
static int upload_data(CloudData* data)
{
	int ret = 0;
	char * buf = NULL;
	cJSON * root = NULL;
	root = create_object(103);
	if(root == NULL)
	{
		ret = -1;
		goto end;
	}
	ret = add_device_object(root);
	if(ret)
		goto end;
	ret = add_streams_object(root, data, 1);
	if(!ret)
	{
		buf = cJSON_PrintUnformatted(root);
		if(buf)
		{
			if(tls_task_callback_with_block(CLOUD_DATA_HANDLER_ID, (start_routine)send_upload_data, buf, 0))
				tls_mem_free(buf);
		}
	}
end:
	if(root)
		cJSON_Delete(root);
	return ret;
}

static int control_resp(CloudData* data)
{
	int ret = 0;
	char * buf = NULL;
	cJSON * root = NULL;
	root = create_object(102);
	if(root == NULL)
	{
		ret = -1;
		goto end;
	}
	ret = add_device_object(root);
	if(ret)
		goto end;
	add_result_object(root, data);
	add_control_resp_object(root, data);
	add_attribute_object(root, data);
	if(!ret)
	{
		buf = cJSON_PrintUnformatted(root);
		if(buf)
		{
			if(tls_task_callback_with_block(CLOUD_DATA_HANDLER_ID, (start_routine)send_upload_data, buf, 0))
				tls_mem_free(buf);
		}
	}
end:
	if(root)
		cJSON_Delete(root);
	return ret;
}
static int snapshot_resp(CloudData* data)
{
	int ret = 0;
	char * buf = NULL;
	cJSON * root = NULL;
	root = create_object(104);
	if(root == NULL)
	{
		ret = -1;
		goto end;
	}
	add_result_object(root, data);
	ret = add_device_object(root);
	if(ret)
		goto end;
	add_attribute_object(root, data);
	ret = add_streams_object(root, data, 0);
	if(!ret)
	{
		buf = cJSON_PrintUnformatted(root);
		if(buf)
		{
			if(tls_task_callback_with_block(CLOUD_DATA_HANDLER_ID, (start_routine)send_upload_data, buf, 0))
				tls_mem_free(buf);
		}
	}
end:
	if(root)
		cJSON_Delete(root);
	return ret;
}

int tls_cloud_upload_data(CloudData* data)
{
	int ret = 0;
	if(data == NULL || server_state != SERVER_STATE_RUNNING)
		return -1;
	switch(data->opt)
	{
		case UPLOAD_REQ:
			ret =  upload_data(data);
			break;
		case CONTROL_RESP:
			ret =  control_resp(data);
			break;
		case SNAPSHOT_RESP:
			ret =  snapshot_resp(data);
			break;
		default:
			break;
	}
	if(data->arg)
		cJSON_Delete((cJSON *)data->arg);
	return ret;
}

int tls_cloud_set_callback(cloud_callback callback)
{
	jd_cloud_callback = callback;
	return 0;
}

int tls_jdclode_init(void* arg)
{
	char* product_uuid = (char*)arg;
	if(jd_cloud_initialized)
	{
		free_jd_param(&jd_param);
	}
	else
	{
		memset(&jd_param, 0, sizeof(JD_PARAM));
		jd_cloud_initialized = 1;
	}
	read_jd_param(&jd_param);
	if(product_uuid != NULL && (jd_param.product_uuid.pParam == NULL || memcmp(product_uuid, jd_param.product_uuid.pParam, jd_param.product_uuid.nLength)))
	{
		if(jd_param.product_uuid.pParam != NULL)
			tls_mem_free(jd_param.product_uuid.pParam);
		jd_param.product_uuid.pParam = strdup(product_uuid);
		jd_param.product_uuid.nLength = strlen(product_uuid);
		write_jd_param(&jd_param);
	}
	return 0;
}

void tls_jdcloud_finish(void)
{
	free_jd_param(&jd_param);
}

int tls_cloud_start_config(void)
{
	/*JD_PARAM param;
	memset(&param, 0, sizeof(JD_PARAM));
	read_jd_param(&param);
	if(param.feed_id.pParam != NULL && param.feed_id.nLength > 0)
	{
		tls_mem_free(param.feed_id.pParam);
		param.feed_id.pParam = NULL;
		param.feed_id.nLength = 0;
		write_jd_param(&param);
	}
	free_jd_param(&param);*/
	return 0;
}
#endif //TLS_CONFIG_CLOUD_JD
