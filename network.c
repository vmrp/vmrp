
#include <stdio.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "./header/bridge.h"
#define NETWORK
#endif

#define USE_NONBLOCK 1

#include "./header/types.h"
#include "./header/net.h"
#include <pthread.h>
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib, "pthreadVC2.lib")

static pthread_t thread_id = 0;
mr_socket_struct mr_soc;

// enum {
//     MR_SOCK_STREAM,
//     MR_SOCK_DGRAM
// };

// enum {
//     MR_IPPROTO_TCP,
//     MR_IPPROTO_UDP
// };

// enum {
//     MR_SOCKET_BLOCK,
//     MR_SOCKET_NONBLOCK
// };

void emu_requestCallback(int32 what, int32 param)
{
	printf("emu_requestCallback(%d, %d)", what, param);
    cb_p0 = param & 0xffffffff;
	return;
}

static char dnsBuf[8192];
static void getHost(char *ptr)
{
	
    struct hostent *hptr;
    int32 ret;

    char **pptr;
    #if defined(__linux__)
	struct hostent hostinfo;
    #endif
	char str[32];
	int err;
	
    usleep(500*1000);

	//查询DNS
#if defined(WIN32)
	if ((hptr = gethostbyname(ptr)) == NULL)
	{
		printf(" error host! %s ",ptr);
		emu_requestCallback(CALLBACK_GETHOSTBYNAME, MR_FAILED);
		return;
	}
    else{
        if (hptr != NULL) {
        if (hptr->h_addrtype == AF_INET) {
            if (hptr->h_addr_list[0] != NULL) {
                struct in_addr addr;
                addr.s_addr = *(u_long *)hptr->h_addr_list[0];
                // printf("%d\n", addr.S_un.S_addr);
                printf("getHost %s\n", inet_ntoa(addr));
                ret = ntohl(addr.S_un.S_addr);
                emu_requestCallback(CALLBACK_GETHOSTBYNAME, ret);
            }
        }
    }
		
    }
#else
	ret = gethostbyname_r(ptr, &hostinfo, dnsBuf, sizeof(dnsBuf), &hptr, &err);
	if(ret || hptr==NULL)
	{
		printf(" error host!");
		//vm_sendMsg_ex(VMMSG_ID_GETHOST, MR_FAILED, 0,0, NULL);
		emu_requestCallback(CALLBACK_GETHOSTBYNAME, MR_FAILED);
		return;
	}
    //主机规范名
	printf(" official hostname:%s", hptr->h_name);

	//获取主机别名列表char *[]
	for (pptr = hptr->h_aliases; *pptr != NULL; pptr++)
	{
		printf("  alias:%s", *pptr);
	}

	switch (hptr->h_addrtype)
	{
	case AF_INET:
	case AF_INET6:
		{
			printf(" first address: %s", inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str)));

			pptr = hptr->h_addr_list; //IP地址列表 char*[]
			for (; *pptr != NULL; pptr++) {
				printf("  address:%s", inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
			}
			memcpy(&ret, hptr->h_addr, 4);

			break;
		}

	default:
		LOGW(" unknown address type");
		break;
	}

	emu_requestCallback(CALLBACK_GETHOSTBYNAME, ntohl(ret));
#endif

	
	//vm_sendMsg_ex(VMMSG_ID_GETHOST, ntohl(ret), 0,0, NULL);
	thread_id = 0;
}




/*
   MR_SUCCESS 成功
   MR_FAILED 失败
   MR_WAITING 使用异步方式进行连接，应用需要轮询该socket的状态以获知连接状况 

   IP地址,如果一个主机的IP地址为218.18.95.203，则值为218<<24 + 18<<16 + 95<<8 + 203= 0xda125fcb
*/
int32 mrc_connect(int32 s, int32 ip, uint16 port, int32 type) {
#ifdef NETWORK
    struct sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_port = htons(port);

    clientService.sin_addr.s_addr = htonl(ip);  //inet_addr("127.0.0.1");
    printf("my_connect(%s)\n", inet_ntoa(clientService.sin_addr));

    if (ip == 0x0A0000AC) {  // 10.0.0.172
        return MR_SUCCESS;
    }

    if (connect((SOCKET)s, (SOCKADDR *)&clientService, sizeof(clientService)) != 0) {
        printf("my_connect(%d) fail\n", ip);
        return MR_FAILED;
    }
    printf("my_connect(%d) suc\n", ip);
    #ifdef USE_NONBLOCK
    return MR_WAITING;
    #else
    return MR_SUCCESS;
    #endif
#else
    return MR_FAILED;
#endif
}

/*
 >=0 返回的Socket句柄 
   MR_FAILED 失败 
*/
int32 mrc_socket(int32 type, int32 protocol) {
#ifdef NETWORK
    type = (type == MR_SOCK_STREAM) ? SOCK_STREAM : SOCK_DGRAM;
    protocol = (protocol == MR_IPPROTO_TCP) ? IPPROTO_TCP : IPPROTO_UDP;
    SOCKET sock = socket(AF_INET, type, protocol);
    if (sock == INVALID_SOCKET) {
        printf("my_socket() fail\n");
        return MR_FAILED;
    }
    printf("my_socket(): %d\n", (int)sock);
    return (int)sock;
#else
    return MR_FAILED;
#endif
}

int32 mrc_closeSocket(int32 s) {
#ifdef NETWORK
    if (shutdown((SOCKET)s, SD_BOTH) != 0) {
        return MR_FAILED;
    }
    if (closesocket((SOCKET)s) != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
#else
    return MR_FAILED;
#endif
}

int32 mrc_closeNetwork(void) {
#ifdef NETWORK
    WSACleanup();
    return MR_SUCCESS;
#else
    return MR_FAILED;
#endif
}

/*  
   MR_SUCCESS 同步模式，初始化成功，不再调用cb
   MR_FAILED （立即感知的）失败，不再调用cb
   MR_WAITING 使用回调函数通知引擎初始化结果 
*/
int32 mrc_initNetwork(MR_INIT_NETWORK_CB cb, const char *mode) {
#ifdef NETWORK
    printf("my_initNetWork\n");
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return MR_FAILED;
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        printf("Could not find a usable version of Winsock.dll\n");
        mrc_closeNetwork();
        return MR_FAILED;
    }
    return MR_SUCCESS;
#else
    printf("network failed\n");
    return MR_FAILED;
#endif
}
/*
   MR_FAILED （立即感知的）失败，不再调用cb
   MR_WAITING 使用回调函数通知引擎获取IP的结果
   其他值 同步模式，立即返回的IP地址，不再调用cb 
*/
int32 mrc_getHostByName(const char *name, MR_GET_HOST_CB cb) {
#ifdef USE_NONBLOCK
	int ret;

	printf("mr_getHostByName(%s)", name);

	mr_soc.callBack = (void*)cb;

#if 0
    int32 ip = mr_getHostByName_block(ptr);
    emu_sendHandlerMessage(EMU_MSG_GET_HSOT, ip, 0, 0);
	//	emu_getHostByName(ptr); //调 Java
#else
	ret = pthread_create(&thread_id, NULL, (void *)getHost, (void *)name);
	if (ret != 0) {
		printf ("mr_getHostByName pthread_create error!");
		return MR_FAILED;
	}
#endif

	return MR_WAITING;
#else
    printf("my_getHostByName(%s)\n", name);
    struct hostent *remoteHost = gethostbyname(name);
    if (remoteHost != NULL) {
        if (remoteHost->h_addrtype == AF_INET) {
            if (remoteHost->h_addr_list[0] != NULL) {
                struct in_addr addr;
                addr.s_addr = *(u_long *)remoteHost->h_addr_list[0];
                // printf("%d\n", addr.S_un.S_addr);
                printf("%s\n", inet_ntoa(addr));
                return ntohl(addr.S_un.S_addr);
            }
        }
    }
    return MR_FAILED;
#endif
}

/*
   >=0 实际发送的数据字节个数
   MR_FAILED Socket已经被关闭或遇到了无法修复的错误。 
*/
int32 mrc_send(int32 s, const char *buf, int len) {
#ifdef NETWORK
    int32 ret = send((SOCKET)s, buf, len, 0);
    if (ret == SOCKET_ERROR) {
        return MR_FAILED;
    }
    return ret;
#else
    return MR_FAILED;
#endif
}

/*
   >=0的整数 实际接收的数据字节个数
   MR_FAILED Socket已经被关闭或遇到了无法修复的错误。 
*/
int32 mrc_recv(int32 s, char *buf, int len) {
#ifdef NETWORK
    int32 ret = recv((SOCKET)s, buf, len, 0);
    if (ret == SOCKET_ERROR) {
        return MR_FAILED;
    }
    return ret;
#else
    return MR_FAILED;
#endif
}

int test() {
#ifdef NETWORK
    mrc_initNetwork(NULL, "cmnet");

    // gcc -Wall a.c -m32 -lws2_32 && ./a.exe
    int ip = mrc_getHostByName("qq.com", NULL);
    printf("ip:0x%X\n", ip);

    int sh = mrc_socket(MR_SOCK_STREAM, MR_IPPROTO_TCP);
    printf("sh:0x%X\n", sh);

    int ret = mrc_connect(sh, ip, 80, MR_SOCKET_NONBLOCK);
    printf("ret:%d\n", ret);

    char *sendData = "GET / HTTP/1.1\r\nHost: qq.com\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    ret = mrc_send(sh, sendData, strlen(sendData));
    printf("len:%d, ret:%d\n", strlen(sendData), ret);

    do {
        char buf[1024 * 1024];
        ret = mrc_recv(sh, buf, sizeof(buf));
        if (ret > 0) {
            buf[ret] = 0;
            printf("Bytes received: %d, %s\n", ret, buf);
        } else if (ret == 0)
            printf("Connection closed\n");
        else
            printf("recv failed with error: %d\n", WSAGetLastError());

    } while (ret > 0);

    mrc_closeNetwork();
#endif
    return 0;
}