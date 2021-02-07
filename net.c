/*
实现网络连接
从mrpoid移植而来，经过适当修改实现兼容

风的影子
*/
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <math.h>

#if defined(__linux__)
#define min(a,b) (a>b?b:a)
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/socket.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <pthread.h>
#elif defined(WIN32)
#include <pthread.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "header/dsm.h"
#include <wsipv6ok.h>
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib, "pthreadVC2.lib")
#endif
#include <stdlib.h>

//#include "emulator.h"
#include "./header/dsm.h"
// #include "mr_types.h"
#include "./header/net.h"
#include "./header/bridge.h"

int dsmNetType;  //网络类型
T_DSM_SOC_STAT socStat[DSM_SUPPROT_SOC_NUM];
mr_socket_struct mr_soc;

void emu_requestCallback(int32 what, int32 param)
{
	printf("emu_requestCallback(%d, %d)", what, param);
    cb_p0 = param & 0xffffffff;
	return;
}

static pthread_t thread_id = 0;


static char* ip2str(uint32 ip, char *out)
{
	sprintf(out, "%d.%d.%d.%d", ip >> 24, (ip & 0xff0000) >> 16, (ip & 0xff00) >> 8, ip & 0xff);
	return out;
}

void DsmSocketInit()
{
	int i =0;

	for(i = 0;i<DSM_SUPPROT_SOC_NUM;i++){
		socStat[i].socketId = MR_FAILED;
		socStat[i].thread_id = i;
	}
		
}

void DsmSocketClose()
{
	int i =0;

	for(i = 0;i<DSM_SUPPROT_SOC_NUM;i++){
		if(socStat[i].socketId != MR_FAILED)
			close(socStat[i].socketId);

		socStat[i].socketId = MR_FAILED;
		socStat[i].socStat = DSM_SOC_CLOSE;
		socStat[i].readStat = DSM_SOC_NOREAD;
		socStat[i].writeStat = DSM_SOC_NOWRITE;
	}
}

int32 mrc_initNetwork(MR_INIT_NETWORK_CB cb, const char *mode)
{
	// if(gEmuEnv.showNet)
		printf("mr_initNetwork(mod:%s)", mode);

    DsmSocketInit();
    mr_soc.callBack = (void*)cb;
#if defined(WIN32)
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
    #endif
    printf("initNetWork ok!\n");
    if(mode != NULL && 0 == strcmp(mode, "cmwap"))
        return MR_FAILED;

    return MR_SUCCESS;
}

int32 mrc_closeNetwork()
{
	// if(gEmuEnv.showNet)
		printf("mr_closeNetwork");

	DsmSocketClose();
	if(thread_id != 0){
		pthread_join(thread_id, NULL);
		thread_id = 0;
	}

	return MR_SUCCESS;
}

//#if 0
//xldebug
static void socketRecv(T_DSM_SOC_STAT *soc){
	if(soc->isProxy){
		soc = &socStat[socStat[soc->thread_id].realSocketId];
	}


//	// if(gEmuEnv.showNet)
		// printf("mr_recv(%d)\n", s);

	// if(soc->socStat == DSM_SOC_ERR)
	// 	return MR_FAILED;
	

	while(soc->readStat == DSM_SOC_READABLE)
	{
		printf("socket_recv id=%d thread_id=%d realid=%d\n",soc->socketId,soc->thread_id,soc->realSocketId);
		soc->bufSize = recv(soc->socketId, soc->socketBuf, SOCKET_BUF_SIZE, 0);
		if((soc->bufSize < 0 && errno == EWOULDBLOCK)){
			soc->bufSize = 0;
		}
		while(soc->bufSize>0){
			usleep(100 * 1000);
		}
		// if(gEmuEnv.showNet) {
			printf("  nread %d %ld\n", soc->bufSize, soc->socketId);
//			writeRecvData((void *)buf, read);
		// }

		if(soc->bufSize >= 0){
			// return read;
		}else if (soc->bufSize < 0 && errno == EWOULDBLOCK) {
			// soc->readStat = DSM_SOC_NOREAD;
			// return 0;
		}else {
			soc->socStat = DSM_SOC_ERR;
			soc->readStat = DSM_SOC_NOREAD;
			printf("recv err.");

			return;
		}
	}
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
	
    usleep(100*1000);

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

//#else

int32 mrc_getHostByName_block(const char *ptr, MR_GET_HOST_CB cb)
{
	char **pptr;
	struct hostent *hptr;
	char str[64];
	int err;
	int32 ret;
    #if defined(WIN32)
struct sockaddr_in in;
    #endif

	LOGI("mr_getHostByName(%s)", ptr);

	//查询DNS
	if ((hptr = gethostbyname(ptr)) == NULL)
	{
		LOGE(" error host!");
		return MR_FAILED;
	}

	//主机规范名
	LOGI(" official hostname:%s", hptr->h_name);

	//获取主机别名列表char *[]
	for (pptr = hptr->h_aliases; *pptr != NULL; pptr++)
		LOGI("  alias:%s", *pptr);

	//IP类型
	switch (hptr->h_addrtype)
	{
	case AF_INET:
	case AF_INET6:
		{
            

            #if defined(WIN32)
			memcpy(&in.sin_addr,hptr->h_addr,sizeof(hptr->h_addr));
			LOGI(" first address: %s", inet_ntoa(in.sin_addr));
            #else
LOGI(" first address: %s",
				inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str)));
            #endif

			pptr = hptr->h_addr_list; //IP地址列表 char*[]
			for (; *pptr != NULL; pptr++)
			{
                #if defined(WIN32)
				LOGI("  address:%s", inet_ntoa(in.sin_addr));
                #else
LOGI("  address:%s",
					inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
                #endif
			}

			memcpy(&ret, hptr->h_addr, 4);

			break;
		}

	default:
		LOGW(" unknown address type");
		break;
	}

	return ntohl(ret);
}

int32 mrc_getHostByName(const char *ptr, MR_GET_HOST_CB cb)
{
	int ret;

	printf("mr_getHostByName(%s)", ptr);

	mr_soc.callBack = (void*)cb;

#if 1
    return mrc_getHostByName_block(ptr,NULL);
#else
	ret = pthread_create(&thread_id, NULL, (void *)getHost, (void *)ptr);
	if (ret != 0) {
		printf ("mr_getHostByName pthread_create error!");
		return MR_FAILED;
	}
#endif

	return MR_WAITING;
}

static int32 dsmGetSocketFreeIndex(void)
{
	int i = 0;

	for(i =0;i<DSM_SUPPROT_SOC_NUM;i++)
	{
		if(socStat[i].socketId == MR_FAILED)
			return i;
	}

	return -1;
}

int socket_set_keepalive (int fd)  
{  
	int ret, error, flag, alive, idle, cnt, intv;  

	/* Set: use keepalive on fd */  
	alive = 1;  
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &alive, sizeof alive) != 0)
	{  
		printf ("Set keepalive error: %s.\n", strerror (errno));
		return -1;  
	}  

	/* 10秒钟无数据，触发保活机制，发送保活包 */
    #if defined(__android__) || defined(__linux__)
	idle = 10;  
	if (setsockopt (fd, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof idle) != 0)  
	{  
		printf ("Set keepalive idle error: %s.\n", strerror (errno));
		return -1;  
	}  

	/* 如果没有收到回应，则5秒钟后重发保活包 */
	intv = 5;  
	if (setsockopt (fd, SOL_TCP, TCP_KEEPINTVL, &intv, sizeof intv) != 0)  
	{  
		printf ("Set keepalive intv error: %s.\n", strerror (errno));
		return -1;  
	}

	/* 连续3次没收到保活包，视为连接失效 */
	cnt = 3;  
	if (setsockopt (fd, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof cnt) != 0)  
	{  
		printf ("Set keepalive cnt error: %s.\n", strerror (errno));
		return -1;  
	}
    #endif

	return 0;  
}  

int32 mrc_socket(int32 type, int32 protocol)
{
	int newType = SOCK_STREAM;
	SOCKET sockfd, index, ret;

	// if(gEmuEnv.showNet)
		printf("mr_socket(type:%d, protocol:%d)", type, protocol);

	index = dsmGetSocketFreeIndex();
	if(index == -1)
		return MR_FAILED;

	if(type == MR_SOCK_DGRAM) {
		newType = SOCK_DGRAM;
	}

	sockfd = socket(AF_INET, newType, 0);
	if(sockfd == INVALID_SOCKET)
	{
        printf("mr_socket fail");
		return MR_FAILED;
	} else {
		socStat[index].socketId = sockfd;
		socStat[index].bufSize = 0;
		socStat[index].socStat = DSM_SOC_OPEN;

		if(type == MR_SOCK_STREAM){
			socStat[index].readStat = DSM_SOC_NOREAD;
			socStat[index].writeStat = DSM_SOC_NOWRITE;
		}else{
			socStat[index].readStat = DSM_SOC_READABLE;
			socStat[index].writeStat = DSM_SOC_WRITEABLE;
		}

		// if(gEmuEnv.showNet)
			printf("mr_socket ok index=%d id=%ld", index,socStat[index].socketId);

		//设置异步模式 xldebug
        #if defined(__android__) || defined(__linux__)
		if((ret = fcntl(sockfd, F_GETFL, 0)) < 0){
			printf("  socket unblock err1.");
		}
		if (fcntl(sockfd, F_SETFL, ret|O_NONBLOCK) < 0){
			printf("  socket unblock err2.");
		}
        #endif

		socket_set_keepalive(sockfd);

		return index;
	}
}

static int32 _selectSocket(int s, long waitms)
{
	int flags, n, error, code;
	SOCKET sockfd=socStat[s].socketId;   
	fd_set wset;   
	struct timeval tval;

	FD_ZERO(&wset);   
	FD_SET(sockfd, &wset);   
	tval.tv_sec = 0;   //等待1秒
	tval.tv_usec = waitms;   

	switch((n = select(sockfd+1, NULL, &wset, NULL, waitms? &tval : NULL)))
	{
	case 0: //继续等待
		// if(gEmuEnv.showNet)
			printf("  select time out, waiting...");
		socStat[s].socStat = DSM_SOC_CONNECTING;
		return MR_WAITING;   

	case -1: //错误
		{
			socStat[s].socStat = DSM_SOC_ERR;
			printf("  select error, sockfd not set");  

			return MR_FAILED;
		}
		break;

	default:
		{
			if (FD_ISSET(sockfd, &wset)) {  
				error = 0;
				socklen_t len = sizeof(error);   

				code = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);   

				/*
				* 如果发生错误，Solaris实现的getsockopt返回-1，
				* 把pending error设置给errno. Berkeley实现的
				* getsockopt返回0, pending error返回给error.
				* 我们需要处理这两种情况
				*/
				if (code < 0 || error) {
					printf("  getsockopt %d err", s);
					socStat[s].socStat = DSM_SOC_ERR;

					return MR_FAILED;   
				}

				socStat[s].socStat = DSM_SOC_CONNECTED;
				socStat[s].readStat = DSM_SOC_READABLE;
				socStat[s].writeStat = DSM_SOC_WRITEABLE;

				// if(gEmuEnv.showNet)
					printf("  socket connected!");

				return MR_SUCCESS;
			} 

			printf("  FD_ISSET false");
			socStat[s].socStat = DSM_SOC_ERR;

			return MR_FAILED;
		}
	}
}

int32 mrc_connect(int32 s, int32 ip, uint16 port, int32 type)
{
	struct sockaddr_in saddr;
	int ret;
	char buf[64];

	// if (gEmuEnv.showNet)
		printf("mr_connect(s:%d, id:%d, ip:%s, port:%d, type:%d)", s,socStat[s].socketId, ip2str(ip, buf), port, type);

	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(ip);
	saddr.sin_port = htons(port);

	errno = 0;
	ret = connect(socStat[s].socketId, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret == 0) { //如果返回0，则表示连接已经建立，这通常是在服务器和客户在同一台主机上时发生。
		socStat[s].socStat = DSM_SOC_CONNECTED;
		socStat[s].readStat = DSM_SOC_READABLE;
		socStat[s].writeStat = DSM_SOC_WRITEABLE;

		// if(gEmuEnv.showNet)
			printf("mr_connect ok connected");
			//xldebug 
			pthread_create(&socStat[s].thread_id, NULL, (void *)socketRecv, (void *)(&socStat[s]));
		return MR_SUCCESS;
	} else if (ret < 0 && errno != EINPROGRESS){ //错误
		// if(gEmuEnv.showNet)
			printf("mr_connect connect err!");
		socStat[s].socStat = DSM_SOC_ERR;
		return MR_FAILED;     
	} else {
		//如果是 10.0.0.172
		if(ip == 0x0A0000AC && dsmNetType != NETTYPE_CMWAP){
			socStat[s].socStat = DSM_SOC_CONNECTED;
			socStat[s].readStat = DSM_SOC_READABLE;
			socStat[s].writeStat = DSM_SOC_WRITEABLE;
			socStat[s].isProxy = 1;
			socStat[s].realConnected = 0;
			printf("mr_connect needProxy!");

			return MR_SUCCESS;
		}

		if(type == MR_SOCKET_NONBLOCK) {
			// if(gEmuEnv.showNet)
				printf("mr_connect waiting...");

			socStat[s].socStat = DSM_SOC_CONNECTING;	

			return MR_WAITING;
		} else { //以阻塞方式连接
			// if(gEmuEnv.showNet)
				LOGW("mr_connect connect block"); //老版本的 MRP 采用阻塞联网，不会查询socket状态

			socStat[s].socStat = DSM_SOC_CONNECTED;
			socStat[s].readStat = DSM_SOC_READABLE;
			socStat[s].writeStat = DSM_SOC_WRITEABLE;

			return _selectSocket(s, 0); //0ms 阻塞
		}
	}
}

int mrc_getSocketState(int s)
{
	// if(gEmuEnv.showNet)
		printf("getSocketState(%d)", s);

	if(socStat[s].socStat == DSM_SOC_CONNECTED){ //已连接
		// if(gEmuEnv.showNet)
			printf("  socket connected!");

		return MR_SUCCESS;
	} else if(socStat[s].socStat == DSM_SOC_CONNECTING) { //正在连接
		return _selectSocket(s, 50); //等 50 ms
	}else{
		printf("  socketfd error! %d", s);
		socStat[s].socStat = DSM_SOC_ERR;

		return MR_FAILED;
	}
}

int32 mrc_closeSocket(int32 s)
{
	if(socStat[s].isProxy){
		mrc_closeSocket(socStat[s].realSocketId);
	}

	int ret = -1;

	if(socStat[s].socketId != MR_FAILED)
		ret = close(socStat[s].socketId);

	// if(gEmuEnv.showNet)
		printf("mr_closeSocket(%d)", s);

	if (ret == 0)
	{
		socStat[s].socketId = MR_FAILED;
		socStat[s].socStat = DSM_SOC_CLOSE;
		socStat[s].readStat = DSM_SOC_NOREAD;
		socStat[s].writeStat = DSM_SOC_NOWRITE;

		return MR_SUCCESS;
	}

	return MR_FAILED;
}

//static void writeRecvData(void *buf, int len)
//{
//	int32 fd = mr_open("net_debug.log", MR_FILE_CREATE|MR_FILE_RDWR);
//	if(fd > 0){
//		mr_seek(fd, 0, MR_SEEK_END);
//		mr_write(fd, "RECV:\n", 6);
//		mr_write(fd, buf, len);
//		mr_write(fd, "\n", 1);
//		mr_close(fd);
//	}
//}

int32 mrc_recv(int32 s, char *buf, int len){
	if(socStat[s].isProxy){
		s = socStat[s].realSocketId;
	}

	int read;

//	// if(gEmuEnv.showNet)
		printf("mr_recv(%d)\n", s);

	if(socStat[s].socStat == DSM_SOC_ERR)
		return MR_FAILED;

	if(socStat[s].readStat == DSM_SOC_READABLE)
	{
		
		// read = recv(socStat[s].socketId, (void*)buf, len, 0);
		read = min(socStat[s].bufSize,len);

		
		// if(gEmuEnv.showNet) {
			printf("  nread %d", read);
//			writeRecvData((void *)buf, read);
		// }

		if(read >= 0){
			memcpy(buf, socStat[s].socketBuf,read);
			socStat[s].bufSize -= read;
			memmove(socStat[s].socketBuf,socStat[s].socketBuf+read,socStat[s].bufSize);
			return read;
		}else {
			socStat[s].socStat = DSM_SOC_ERR;
			socStat[s].readStat = DSM_SOC_NOREAD;
			printf("recv err.");

			return MR_FAILED;
		}
	}

	return 0;
}

//static void writeSendData(int32 s, void *buf, int len)
//{
//	int32 fd = mr_open("net_debug.log", MR_FILE_CREATE|MR_FILE_RDWR);
//	if(fd > 0){
//		char buf[128];
//		int l = 0;
//
//		mr_seek(fd, 0, MR_SEEK_END);
//		l += sprintf(buf, "socket=%d SEND\n", socStat[s].socketId);
//		mr_write(fd, buf, l);
//		mr_write(fd, buf, len);
//		mr_write(fd, "\n", 1);
//		mr_close(fd);
//	}
//}

void readLine(const char *p, char *out)
{
	const char *p1 = p;

	while(*p1 && *p1!='\r' && *p1!='\n') p1++;

	strncpy(out, p, p1-p);
}

void getRealIP(const char *buf, int len, int32 *ip, int32 *prot)
{
	const char *p;
	char line[128] = {0};

	p = strstr(buf, "Host:");
	if(p)
	{
		char ipstr[64] = {0};
		char portstr[8] = "80";

		readLine(p, line);
		printf("%s", line);

		sscanf(line, "Host: %[^:]:%s", ipstr, portstr);

		*ip = mrc_getHostByName_block(ipstr,NULL);
		*prot = atoi(portstr);
	}
}

int32 mrc_send(int32 s, const char *buf, int len)
{
	// if(gEmuEnv.showNet)
		printf("mr_send %d %d", s, len);

	if(socStat[s].isProxy)
	{
//		writeSendData(s, (void *)buf, len);
//		printf(buf);

		if(!socStat[s].realConnected){ //没有连接上
			//解析真实IP
			int32 ip, port;
			getRealIP(buf, len, &ip, &port);

			socStat[s].realSocketId = mrc_socket(MR_SOCK_STREAM, MR_IPPROTO_TCP);
			mrc_connect(socStat[s].realSocketId, ip, port, MR_SOCKET_BLOCK);

			socStat[s].realConnected = 1;
		}

		s = socStat[s].realSocketId;
	}

	int write;

//	// if(gEmuEnv.showNet)
//		printf("mr_send(%d)", s);

	if(socStat[s].socStat == DSM_SOC_ERR)
		return MR_FAILED;

	if(socStat[s].writeStat == DSM_SOC_WRITEABLE)
	{
		write = send(socStat[s].socketId, (void*)buf, len, 0);

		// if(gEmuEnv.showNet) {
			printf("  nwrite %d\n", write);
		// }

		if(write >= 0) {
			return write;
		} else if(write < 0 && errno == EWOULDBLOCK) {
			//socStat[s].writeStat = DSM_SOC_NOWRITE;
			return 0;
		} else {
			socStat[s].socStat = DSM_SOC_ERR;
			socStat[s].writeStat = DSM_SOC_NOWRITE;
			printf("mr_send err\n");
			return MR_FAILED;
		}
	}

	return 0;
}

int32 mrc_recvfrom(int32 s, char *buf, int len, int32 *ip, uint16 *port)
{
	// if(gEmuEnv.showNet)
		printf("mr_recvfrom %d ip=%s:%d", s, ip, *port);

	if(socStat[s].socStat == DSM_SOC_ERR)
		return MR_FAILED;

	if(socStat[s].readStat == DSM_SOC_READABLE)
	{
		if(ip != NULL && port != NULL)
		{
			int read;
			struct sockaddr_in fromaddr;
			socklen_t addr_len;

			read = recvfrom(socStat[s].socketId, buf, len, 0, (struct sockaddr *)&fromaddr, &addr_len);

			// if(gEmuEnv.showNet)
				printf("mr_recvfrom read: %s size=%d\n", buf, read);

			*port = ntohs(fromaddr.sin_port);
			*ip = ntohl(fromaddr.sin_addr.s_addr);
			if(read >= 0) {
				return read;
			} else if (read < 0 && errno == EWOULDBLOCK) {
				//socStat[s].readStat = DSM_SOC_NOREAD;
				return 0;
			} else {
				printf("mr_recvfrom fail");
			}
		}

		return MR_FAILED;
	}

	return 0;
}

int32 mrc_sendto(int32 s, const char *buf, int len, int32 ip, uint16 port)
{
	char str[32];

	// if(gEmuEnv.showNet)
		printf("mr_sendto %d ip=%s:%d %s)", s, ip2str(ip, str), port, buf);

	if(socStat[s].socStat == DSM_SOC_ERR)
		return MR_FAILED;

	if(socStat[s].writeStat == DSM_SOC_WRITEABLE)
	{
		struct sockaddr_in toaddr;
		int write;

		memset(&toaddr, 0, sizeof(toaddr));
		toaddr.sin_family = AF_INET;
		toaddr.sin_port = htons(port);
		toaddr.sin_addr.s_addr = htonl(ip);

		write = sendto(socStat[s].socketId, buf, len, 0, (struct sockaddr *)&toaddr, sizeof(struct sockaddr));

		// if(gEmuEnv.showNet)
			printf("mr_sendto writ %d byte", write);

		if(write >= 0) {
			return write;
		} else if(write < 0 && errno == EWOULDBLOCK) {
			//socStat[s].writeStat = DSM_SOC_NOWRITE;
			return 0;
		} else {
			socStat[s].socStat = DSM_SOC_ERR;
			socStat[s].writeStat = DSM_SOC_NOWRITE;
			printf("mr_sendto fail");
			return MR_FAILED;
		}
	}

	return 0;
}
