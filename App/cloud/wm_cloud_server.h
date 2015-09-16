#ifndef __WM_CLOUD_SERVER_H__
#define __WM_CLOUD_SERVER_H__

#include "wm_config.h"

#if TLS_CONFIG_CLOUD
#include "wm_sockets.h"
#if TLS_CONFIG_HTTP_CLIENT_SECURE
#include "matrixsslApi.h"
#endif

#define CLOUD_SERVER_TASK_ID (0)
#define CLOUD_DATA_HANDLER_ID (1)

#define max(a, b)   (((a)>(b))? (a):(b))
#define SOCKET_TCP 1
#define SOCKET_CLINET 2
#define SOCKET_SSL  4

typedef struct _SOCKET{
	int socket_num;
	struct sockaddr * sock_addr;
	u8 sock_type;
	u8 connected;
#if TLS_CONFIG_HTTP_CLIENT_SECURE
	ssl_t * ssl;
#endif
}SOCKET;

#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)


#define SERVER_STATE_STOPPED 0
#define SERVER_STATE_RUNNING 1
#define SERVER_STATE_STOPPING 2

typedef struct CServerSockArray {
	SOCKET *socket1;
	SOCKET *socket2;
	SOCKET *socket3;
	SOCKET *socket4;
	SOCKET *socket5;
}CloudServerSockArray;

typedef struct CReadData{
	SOCKET *socket;
	char * read_data;
	u32     data_len;
	struct sockaddr_in sin_recv;
}CloudReadData;

void read_data_handler(void * the_data);
int get_cloud_sockets(CloudServerSockArray *cloudSock);
void send_heartbeat_data(void * arg);
int get_sockets(CloudServerSockArray *cloudSock);
void free_read_data(CloudReadData *data);
int socket_sendto(SOCKET *sock, const void *data, size_t size, int flags,
       const struct sockaddr *to, socklen_t tolen);
int sock_close(	SOCKET *sock);

#endif //TLS_CONFIG_CLOUD
#endif

