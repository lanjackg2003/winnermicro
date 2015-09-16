#include "wm_task.h"
#include "wm_sockets.h"
#include "wm_debug.h"
#include "wm_cloud.h"
#include "wm_cloud_server.h"

#if TLS_CONFIG_CLOUD

#define CLOUD_SERVER_TASK_STK_SIZE  512 
OS_STK         cloud_server_task_stk[CLOUD_SERVER_TASK_STK_SIZE];
#define CLOUD_DATA_TASK_STK_SIZE  1200 
OS_STK         cloud_data_task_stk[CLOUD_DATA_TASK_STK_SIZE];


#if TLS_CONFIG_HTTP_CLIENT_SECURE
	extern int HTTPWrapperSSLConnect        (ssl_t **ssl_p,int s,const struct sockaddr *name,int namelen,char *hostname);
	extern int HTTPWrapperSSLSend              (ssl_t *ssl,int s,char *buf, int len,int flags);
	extern int HTTPWrapperSSLRecv              (ssl_t *ssl,int s,char *buf, int len,int flags);
	extern int HTTPWrapperSSLClose             (ssl_t *ssl, int s);
#endif
extern int tls_jdclode_init(void* arg);
extern void tls_jdcloud_finish(void);
u8 server_state = SERVER_STATE_STOPPED;
static CloudServerSockArray *cloudSock = NULL;
static u8 cloud_server_task_run = 0;
static u8 cloud_data_task_run = 0;
static int cloud_init_internal(void);
static void fdset_if_valid(SOCKET *sock, fd_set *set)
{
	if (sock && sock->socket_num != INVALID_SOCKET) {
		FD_SET(sock->socket_num, set);
	}
}
static void free_socket(SOCKET * sock)
{
	if(sock)
	{
		if(sock->sock_addr)
		{
			tls_mem_free(sock->sock_addr);
			sock->sock_addr = NULL;
		}
		tls_mem_free(sock);
		TLS_DBGPRT_INFO("free sock %p\n", sock);
	}
}
int sock_close(
	/*! Socket descriptor. */
	SOCKET *sock)
{
	int ret = -1;
	if (sock == NULL || sock->socket_num == INVALID_SOCKET)
		return 0;
#if TLS_CONFIG_HTTP_CLIENT_SECURE
	if((sock->sock_type & SOCKET_SSL) && sock->ssl)
	{
		// TLS Close
		TLS_DBGPRT_INFO("start HTTPWrapperSSLClose\n");
		ret = HTTPWrapperSSLClose(sock->ssl, sock->socket_num);
		TLS_DBGPRT_INFO("HTTPWrapperSSLClose ret=%d\n", ret);
		sock->ssl = NULL;
	}
#endif //TLS_CONFIG_HTTP_CLIENT_SECURE
	// Gracefully close it
	shutdown(sock->socket_num,0x01);
	ret = closesocket(sock->socket_num);
	sock->socket_num = INVALID_SOCKET;
		
	return ret;
}
#define READ_BUFSIZE (1024)
static char READ_BUFFER[READ_BUFSIZE];
static int readFromSocket(SOCKET *socket)
{
	char *requestBuf = NULL;
	struct sockaddr_in __ss;
	CloudReadData *data = NULL;
	socklen_t socklen = sizeof(__ss);
	u32 byteReceived = 0;
	//char ntop_buf[22];
	requestBuf = READ_BUFFER;
	/* in case memory can't be allocated, still drain the socket using a
	 * static buffer. */
#if TLS_CONFIG_HTTP_CLIENT_SECURE
	if((socket->sock_type & SOCKET_SSL) && socket->ssl){
		byteReceived = HTTPWrapperSSLRecv(socket->ssl,socket->socket_num,requestBuf,READ_BUFSIZE - (size_t)1,MSG_DONTWAIT);
	}
	else
#endif
	{
		byteReceived = recvfrom(socket->socket_num, requestBuf, READ_BUFSIZE - (size_t)1, 0,
				(struct sockaddr *)&__ss, &socklen);
	}
	TLS_DBGPRT_INFO("recvfrom socket->socket_num=%d, byteReceived=%d\n", socket->socket_num, byteReceived);
	if (byteReceived > 0) {
		requestBuf[byteReceived] = '\0';
		/*
		switch (__ss.sin_family) {
		case AF_INET:
			inet_ntop(AF_INET,
				  &((struct sockaddr_in *)&__ss)->sin_addr,
				  ntop_buf, sizeof(ntop_buf));
			break;
		default:
			memset(ntop_buf, 0, sizeof(ntop_buf));
			strncpy(ntop_buf, "<Invalid address family>",
				sizeof(ntop_buf) - 1);
			TLS_DBGPRT_INFO("family = %d\n", __ss.sin_family);
		}*/
		data = tls_mem_alloc(sizeof(CloudReadData));
		if (data) {
			memset(data, 0, sizeof(CloudReadData));
			data->socket = socket;
			data->data_len = byteReceived+1;
			data->read_data = tls_mem_alloc(data->data_len);
			if(data->read_data)
				memcpy(data->read_data, READ_BUFFER, data->data_len);
			else
			{
				tls_mem_free(data);
				return byteReceived;
			}
			memcpy(&data->sin_recv, &__ss, sizeof(struct sockaddr));
			if (tls_task_callback_with_block(CLOUD_DATA_HANDLER_ID, (start_routine)read_data_handler, data, 0) != ERR_OK)
			{
				TLS_DBGPRT_INFO("tls_task_callback_with_block err.\n");
				free_read_data(data);
			}
		}
	}
	return byteReceived;
}
static int socket_read(SOCKET *rsock, fd_set *set)
{
	int ret = 0;
	if (rsock && rsock->socket_num != INVALID_SOCKET && FD_ISSET(rsock->socket_num, set)) {
		TLS_DBGPRT_INFO("rsock->socket_num=%d\n", rsock->socket_num);
		ret = readFromSocket(rsock);
		if(ret < 0)
		{
			sock_close(rsock);
			//free_socket(rsock);
		}
	}
	return ret;
}
static void free_socket_array()
{
	if(cloudSock)
	{
		free_socket(cloudSock->socket1);
		cloudSock->socket1 = NULL;
		free_socket(cloudSock->socket2);
		cloudSock->socket2 = NULL;
		free_socket(cloudSock->socket3);
		cloudSock->socket3 = NULL;
		free_socket(cloudSock->socket4);
		cloudSock->socket4 = NULL;
		free_socket(cloudSock->socket5);
		cloudSock->socket5 = NULL;
		tls_mem_free(cloudSock);
		TLS_DBGPRT_INFO("free cloudSock %p\n", cloudSock);
		cloudSock = NULL;
	}
}

int socket_sendto(SOCKET* sock, const void *data, size_t size, int flags,
       const struct sockaddr *to, socklen_t tolen)
{
	int ret = 0;
	if(sock->socket_num == INVALID_SOCKET || server_state != SERVER_STATE_RUNNING)
		return ret;
	if((sock->sock_type & SOCKET_TCP)){
#if TLS_CONFIG_HTTP_CLIENT_SECURE
		if((sock->sock_type & SOCKET_SSL)){
			ret = HTTPWrapperSSLSend(sock->ssl,sock->socket_num,(char *)data,size,flags);
			TLS_DBGPRT_INFO("HTTPWrapperSSLSend ret=%d\n", ret);
		}
		else
#endif
		{
			ret = send(sock->socket_num,data,size,flags);
		}
	}
	else{
		ret = sendto(sock->socket_num, data, size, flags, to, tolen);
	}
	if(ret == SOCKET_ERROR){
		sock_close(sock);
		//free_socket(sock);
		return ret;
	}
	return ret;
}
static void run_server(void * arg)
{
	fd_set expSet;
	fd_set rdSet;
	int maxCloudSock;
	int ret = 0;
	struct timeval timeout;
	cloudSock = (CloudServerSockArray *)arg;

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	while (server_state == SERVER_STATE_RUNNING) {
		maxCloudSock = 0;
		if(cloudSock->socket1 && cloudSock->socket1->connected)
			maxCloudSock = max(maxCloudSock, cloudSock->socket1->socket_num);
		if(cloudSock->socket2 && cloudSock->socket2->connected)
			maxCloudSock = max(maxCloudSock, cloudSock->socket2->socket_num);
		if(cloudSock->socket3 && cloudSock->socket3->connected)
			maxCloudSock = max(maxCloudSock, cloudSock->socket3->socket_num);
		if(cloudSock->socket4 && cloudSock->socket4->connected)
			maxCloudSock = max(maxCloudSock, cloudSock->socket4->socket_num);
		if(cloudSock->socket5 && cloudSock->socket5->connected)
			maxCloudSock = max(maxCloudSock, cloudSock->socket5->socket_num);
		++maxCloudSock;
		FD_ZERO(&rdSet);
		FD_ZERO(&expSet);
		fdset_if_valid(cloudSock->socket1, &rdSet);
		fdset_if_valid(cloudSock->socket2, &rdSet);
		fdset_if_valid(cloudSock->socket3, &rdSet);
		fdset_if_valid(cloudSock->socket4, &rdSet);
		fdset_if_valid(cloudSock->socket5, &rdSet);
		/* select() */
		ret = select((int) maxCloudSock, &rdSet, NULL, &expSet, &timeout);
		TLS_DBGPRT_INFO("select end.ret=%d\n", ret);
		if (ret == SOCKET_ERROR) {
			continue;
		} else {
			do{
				ret = socket_read(cloudSock->socket1, &rdSet);
				if(ret < 0)
					break;
				ret = socket_read(cloudSock->socket2, &rdSet);
				if(ret < 0)
					break;
				ret = socket_read(cloudSock->socket3, &rdSet);
				if(ret < 0)
					break;
				ret = socket_read(cloudSock->socket4, &rdSet);
				if(ret < 0)
					break;
				ret = socket_read(cloudSock->socket5, &rdSet);
				if(ret < 0)
					break;
			}while(0);
			if(ret < 0)
			{
				TLS_DBGPRT_INFO("start to reconnect to socket.\n");
				tls_cloud_finish(0);
				while(tls_task_add_timeout(CLOUD_DATA_HANDLER_ID, 5000, (sys_timeout_handler)cloud_init_internal, NULL) != ERR_OK)
				{
					TLS_DBGPRT_INFO("tls_task_add_timeout cloud_init_internal err\n");
					tls_os_time_delay(1);
				}
			}
		}
	}
	/* Close all sockets. */
	sock_close(cloudSock->socket1);
	sock_close(cloudSock->socket2);
	sock_close(cloudSock->socket3);
	sock_close(cloudSock->socket4);
	sock_close(cloudSock->socket5);
	/* Free minisock. */
	free_socket_array();
	server_state = SERVER_STATE_STOPPED;
}

int get_sockets(CloudServerSockArray *cloudSock){
	int ret = 0, i;
	SOCKET ** socks = NULL;
	SOCKET * sock = NULL;
	struct sockaddr * sin = NULL;
	ret = get_cloud_sockets(cloudSock);
	if(ret)
		return ret;
	socks = (SOCKET **)cloudSock;
	for(i=0; i<5; i++){
		sock = socks[i];
		TLS_DBGPRT_INFO("sock = %p\n", sock);
		if(sock == NULL || sock->socket_num >= 0)
			continue;
		
		sin = (struct sockaddr *)sock->sock_addr;
		if(sock->sock_type == 0){//UDP
			sock->socket_num = socket(AF_INET,SOCK_DGRAM, IPPROTO_UDP);
			TLS_DBGPRT_INFO("sock->socket_num = %d\n", sock->socket_num);
			if(sock->socket_num < 0)
				return -1;
			ret = bind(sock->socket_num, sin, sizeof(struct sockaddr));
			TLS_DBGPRT_INFO("bind ret = %d\n", ret);
			if(ret){
				sock_close(sock);
				return ret;
			}
			else
				sock->connected = 1;
		}
		else{
			if((sock->sock_type & SOCKET_CLINET))
			{
				struct sockaddr ServerAddr;
				sock->socket_num = socket(AF_INET,	    // Address family 
            				SOCK_STREAM,			                    // Socket type     
           				 IPPROTO_TCP);		                        // Protocol         
           			TLS_DBGPRT_INFO("sock->socket_num = %d\n", sock->socket_num);
           			if(sock->socket_num < 0)
					return -1;
#if TLS_CONFIG_HTTP_CLIENT_SECURE
				memset(&ServerAddr, 0, sizeof(struct sockaddr));
				memcpy(&ServerAddr, sock->sock_addr, sizeof(struct sockaddr));
				if((sock->sock_type & SOCKET_SSL)){
					ret = HTTPWrapperSSLConnect(&sock->ssl,sock->socket_num,	// Socket
				                &ServerAddr,	        // Server address    
				                sizeof(struct sockaddr),                  // Length of server address structure
				                "desktop");	                            // Hostname (ToDo: Fix this)	              
           				TLS_DBGPRT_INFO("HTTPWrapperSSLConnect ret = %d\n", ret);
				}
				else
#endif
				{
					ret = connect(sock->socket_num, sock->sock_addr, sizeof(struct sockaddr));
           				TLS_DBGPRT_INFO("connect ret = %d\n", ret);
				}
				if(ret){
					sock_close(sock);
					return ret;
				}
				else
					sock->connected = 1;
			}
		}
	}
	return 0;
}

static int cloud_init_internal(void)
{
	int ret = 0;
	if(server_state != SERVER_STATE_STOPPED)
		return server_state;
	cloudSock = tls_mem_alloc(sizeof(CloudServerSockArray));
	if(cloudSock == NULL)
	{
		ret = ERR_MEM;
		goto out;
	}
	memset(cloudSock, 0, sizeof(CloudServerSockArray));
	tls_jdclode_init(NULL);
	ret = get_sockets(cloudSock);
	if(ret)
	{	
		sock_close(cloudSock->socket1);
		sock_close(cloudSock->socket2);
		sock_close(cloudSock->socket3);
		sock_close(cloudSock->socket4);
		sock_close(cloudSock->socket5);
		goto out;
	}
	ret = tls_task_add_timeout(CLOUD_DATA_HANDLER_ID, 5000, send_heartbeat_data, cloudSock);
	if(ret)
	{
		goto out;
	}
	server_state = SERVER_STATE_RUNNING;
	ret = tls_task_callback_with_block(CLOUD_SERVER_TASK_ID, (start_routine)run_server, cloudSock, 0);
	if(ret)
	{
		server_state = SERVER_STATE_STOPPED;
		goto out;
	}
out:
	if(ret)
	{
		free_socket_array();
		tls_cloud_finish(0);
		tls_task_add_timeout(CLOUD_DATA_HANDLER_ID, 5000, (sys_timeout_handler)cloud_init_internal, NULL);
	}
	TLS_DBGPRT_INFO("tls_cloud_init ret=%d\n", ret);
	return ret;
}

int tls_cloud_init(void * arg)
{
	int ret = 0;
	int timeout = 5000;
	//CloudServerSockArray *cloudSock = NULL;
	struct task_parameter cloud_server_task_param = {
		.mbox_size = 1,
		.name = "Cloud Server Task",
		.stk_size = CLOUD_SERVER_TASK_STK_SIZE,
		.stk_start = (u8 *)cloud_server_task_stk,
		.task_id = CLOUD_SERVER_TASK_ID,
	};
	 struct task_parameter cloud_data_task_param = {
		.mbox_size = 32,
		.name = "Cloud Data Task",
		.stk_size = CLOUD_DATA_TASK_STK_SIZE,
		.stk_start = (u8 *)cloud_data_task_stk,
		.task_id = CLOUD_DATA_HANDLER_ID,
	};
	tls_jdclode_init(arg);
	if(!cloud_data_task_run)
	{
		ret = tls_task_run(&cloud_data_task_param);
		if(ret)
			goto out;
		cloud_data_task_run = 1;
	}
	if(!cloud_server_task_run)
	{
		ret = tls_task_run(&cloud_server_task_param);
		if(ret)
			goto out;
		cloud_server_task_run = 1;
	}
	tls_cloud_finish(0);
	if(server_state == SERVER_STATE_STOPPED)
		ret = tls_task_callback_with_block(CLOUD_DATA_HANDLER_ID, (start_routine)cloud_init_internal, NULL, 0);
	else
		ret = tls_task_add_timeout(CLOUD_DATA_HANDLER_ID, timeout, (sys_timeout_handler)cloud_init_internal, NULL);
out:
	TLS_DBGPRT_INFO("tls_cloud_init ret=%d\n", ret);
	return ret;
}

void tls_cloud_finish(u8 block)
{
	if(server_state != SERVER_STATE_RUNNING)
		return;
	server_state = SERVER_STATE_STOPPING;
	tls_task_untimeout(CLOUD_DATA_HANDLER_ID, send_heartbeat_data, cloudSock);
	tls_jdcloud_finish();
	if(block)
	{
		while(server_state != SERVER_STATE_STOPPED)
		{
			tls_os_time_delay(10);
		}
	}
}

void free_read_data(CloudReadData *data)
{
	if(data == NULL)
		return;
	if(data->read_data != NULL)
		tls_mem_free(data->read_data);
	tls_mem_free(data);
}

#endif //TLS_CONFIG_CLOUD

