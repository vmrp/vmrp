
#if defined(__linux__) || defined(__android__)
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <asm/socket.h>
#include <linux/socket.h>
typedef int32_t SOCKET;
#elif defined(WIN32)

#include <winsock2.h>



#endif
typedef enum {
	NETTYPE_WIFI=0,
	NETTYPE_CMWAP=1,
	NETTYPE_CMNET=2,
	NETTYPE_UNKNOW=3
}AND_NETTYPE;

#define SOCKET_BUF_SIZE 256

typedef struct
{
	SOCKET socketId; //socket 句柄
	SOCKET realSocketId; //真实 socket 句柄（代理有效）
      pthread_t thread_id;
	int isProxy; //代理标志
	int realConnected; //真实连接上标志

	int socStat;
	int readStat;
	int writeStat;
      char socketBuf[SOCKET_BUF_SIZE];
      int bufSize;
}T_DSM_SOC_STAT;

// #if defined(WIN32)
// #define TCP_KEEPIDLE 4
// #define TCP_KEEPINTVL 5
// #define TCP_KEEPCNT 6
// #define SOL_TCP 6
// #define SOL_UDP 17
#if defined(WIN32)
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#ifndef O_NONBLOCK
#define O_NONBLOCK 00004000
#endif

#else
#define INVALID_SOCKET -1
#endif
// #endif

/*
enum {
   MR_SOCKET_BLOCK,          //阻塞方式（同步方式）
   MR_SOCKET_NONBLOCK       //非阻塞方式（异步方式）
};



enum
{
   MR_SOCK_STREAM,
   MR_SOCK_DGRAM
};

enum
{
   MR_IPPROTO_TCP,
   MR_IPPROTO_UDP
};
*/

enum {
   MR_SOCKET_BLOCK,          //阻塞方式（同步方式）
   MR_SOCKET_NONBLOCK       //非阻塞方式（异步方式）
};

enum
{
   MR_IPPROTO_TCP,
   MR_IPPROTO_UDP
};

enum {
	CALLBACK_PLAYMUSIC = 0x1001,
	CALLBACK_GETHOSTBYNAME,
	CALLBACK_TIMER_OUT,

	CALLBACK_MAX
};

enum
{
   MR_SOCK_STREAM,
   MR_SOCK_DGRAM
};

typedef enum
{
	DSM_SOC_NOREAD,
	DSM_SOC_READABLE
}T_DSM_SOC_READ_STAT;

typedef enum
{
	DSM_SOC_NOWRITE,
	DSM_SOC_WRITEABLE
}T_DSM_SOC_WRITE_STAT;

typedef enum
{
	DSM_SOC_CLOSE,
	DSM_SOC_OPEN,
	DSM_SOC_CONNECTING,
	DSM_SOC_CONNECTED,
	DSM_SOC_ERR
}T_DSM_SOC_STAT_ENUM;

typedef struct
{     
	void *callBack;
} mr_socket_struct;

#define DSM_SUPPROT_SOC_NUM                        (5)
extern int dsmNetType;

/*函数mr_initNetwork使用的回调函数定义*/
typedef int32 (*MR_INIT_NETWORK_CB)(int32 result);

/*函数mr_initNetwork使用的回调函数定义*/
typedef int32 (*MR_CONNECT_CB)(int32 result);

/*函数mr_getHostByName使用的回调函数定义*/
typedef int32 (*MR_GET_HOST_CB)(int32 ip);

int32 mrc_getNetworkType();
//extern T_EMULATOR_CFG		gEmulatorCfg; //保存模拟器配置


/********************************网络接口********************************/

/*
取得网络ID。

返回:
      MR_NET_ID_MOBILE  移动GSM
      MR_NET_ID_CN   联通GSM
      MR_NET_ID_CDMA 联通CDMA
      MR_NET_ID_NONE 未插卡或网络错误
*/
int32 mrc_getNetworkID(void);

/*
网络初始化回调函数
输入:
result:
   MR_SUCCESS  初始化成功
   MR_FAILED      初始化失败
返回值:
   MR_SUCCESS  操作成功
   MR_FAILED      操作失败
函数的返回值仅作为将来升级版本保留，目前mythroad
不关心函数的返回值。
*/
typedef int32 (*MR_INIT_NETWORK_CB)(int32 result);

/*
网络初始化，如果没有拨号，进行拨号操作。
这里需要注意的是，本文档描述的所有网络接口函
数在实现时建议优先考虑采用非阻塞方式。
若网络初始化使用异步模式，使用回调函数通知引
擎初始化结果。

输入:
cb	当网络初始化使用异步模式时，使用该回调函数
通知应用初始化结果
mode	拨号方式，"CMNET"或" CMWAP"的拨号方式。

返回:
      MR_SUCCESS  同步模式，初始化成功，不再调用cb
      MR_FAILED   （立即感知的）失败，不再调用cb
      MR_WAITING  使用回调函数通知引擎初始化结果
*/
int32 mrc_initNetwork(MR_INIT_NETWORK_CB cb, const char *mode);

/*
断开拨号连接。

输入:

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_closeNetwork(void);

/*
获取主机IP回调函数
输入:
ip: 
   MR_FAILED       获取IP失败
   其他值      IP地址
返回值:
   MR_SUCCESS  操作成功
   MR_FAILED      操作失败
函数的返回值仅作为将来升级版本保留，目前mythroad
不关心函数的返回值。
*/
typedef int32 (*MR_GET_HOST_CB)(int32 ip);

/*
	通过主机名获得该主机的IP地址值，如果一个主机
	的IP地址为218.18.95.203，则值为218<<24 + 18<<16 + 95<<8 + 203
	= 0xda125fcb。
      若获取主机IP使用异步模式，使用回调函数通知引
      擎获取IP的结果。

输入:
name  主机名
cb      回调函数


返回:
      MR_FAILED   （立即感知的）失败，不再调用cb
      MR_WAITING  使用回调函数通知引擎获取IP的结果
      其他值   同步模式，立即返回的IP地址，不再调用cb
*/
int32 mrc_getHostByName(const char *name, MR_GET_HOST_CB cb);

/*
	创建一个socket。

输入:
 type	 Socket类型：
      MR_SOCK_STREAM
      MR_SOCK_DGRAM
 protocol	具体协议类型:
      MR_IPPROTO_TCP，
      MR_IPPROTO_UDP

返回:
      >=0              返回的Socket句柄
      MR_FAILED    失败
*/
int32 mrc_socket(int32 type, int32 protocol);

/*
	建立TCP连接。

输入:
 s       打开的socket句柄。
 ip      IP地址
 port    端口号
 type:
            MR_SOCKET_BLOCK          //阻塞方式（同步方式）
            MR_SOCKET_NONBLOCK       //非阻塞方式（异步方式）

返回:
      MR_SUCCESS  成功
      MR_FAILED      失败
      MR_WAITING   使用异步方式进行连接，应用需要轮询
                            该socket的状态以获知连接状况
*/
int32 mrc_connect(int32 s, int32 ip, uint16 port, int32 type);


/*
获取socket connect 状态（主要用于TCP的异步连接）
返回：

输入:
Socket句柄

返回:
      MR_SUCCESS ：  连接成功
      MR_FAILED  ：连接失败
      MR_WAITING ：连接中
      MR_IGNORE  ：不支持该功能
*/
int32 mrc_getSocketState(int32 s);

/*
 	关闭一个socket连接。

输入:
s  打开的socket句柄

返回:
      MR_SUCCESS  成功
      MR_FAILED   失败
*/
int32 mrc_closeSocket(int32 s);

/*
 	从网络接收数据。

输入:
s  打开的socket句柄。
len   缓冲区大小。

输出:
buf   缓冲区，存放接收到的数据。

返回:
      >=0的整数   实际接收的数据字节个数
      MR_FAILED          Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_recv(int32 s, char *buf, int len);

/*
 	从指定地址接收数据。

输入:
s  打开的socket句柄。
len   缓冲区大小。
ip   对端IP地址
port 对端端口号

输出:
buf   缓冲区，存放接收到的数据。


返回:
      >=0的整数   实际接收的数据字节个数
      MR_FAILED   Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_recvfrom(int32 s, char *buf, int len, int32 *ip, uint16 *port);

/*
 	发送数据。

输入:
s  打开的socket句柄
len   缓冲区大小

输出:
buf   要发送数据的缓冲区

返回:
      >=0             实际发送的数据字节个数
      MR_FAILED   Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_send(int32 s, const char *buf, int len);

/*
 	向指定地址发送数据。

输入:
s  打开的socket句柄
len   缓冲区大小
ip   对端IP地址
port 对端端口号

输出:
buf   要发送数据的缓冲区

返回:
      >=0               实际发送的数据字节个数
      MR_FAILED     Socket已经被关闭或遇到了无法修复的错误。
*/
int32 mrc_sendto(int32 s, const char *buf, int len, int32 ip, uint16 port);


