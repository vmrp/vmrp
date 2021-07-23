
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "./include/network.h"
#include "./include/posix_sockets.h"

// #define NETWORK_SUPPORT

#if defined(__EMSCRIPTEN__) && defined(NETWORK_SUPPORT)
#include <emscripten.h>
#include <emscripten/websocket.h>
#include <emscripten/threading.h>

EMSCRIPTEN_WEBSOCKET_T bridgeSocket = 0;

EMSCRIPTEN_WEBSOCKET_T emscripten_init_websocket_to_posix_socket_bridge(const char* bridgeUrl);
#endif


typedef struct {
    SOCKET_T s;
    uint32_t sendCounter;
    int32_t realState;  // 真正的连接状态
    int32_t state;      // cmwap模式下是一个伪状态，cmnet模式下与realState的值始终相同
} mSocket;

static int isCMWAP = FALSE;
static struct rb_root sockets = RB_ROOT;

static int parseHostPort(char* str, char* outHost, int outHostLen, uint16_t* outPort) {
    int i;
    char* h = strstr(str, "://");
    if (h == NULL) {
        return -1;
    }
    h += 3;  // 跳过'://'

    for (i = 0; i < outHostLen; i++) {
        if (*h == '\0' || *h == ':' || *h == '/') {
            break;
        }
        outHost[i] = *h;
        h++;
    }
    outHost[i] = '\0';

    char* p = strstr(h, ":");
    if (p == NULL) {
        *outPort = 80;
    } else {
        char port[6];
        p += 1;  // 跳过':'
        for (i = 0; i < sizeof(port); i++) {
            if (*p == '\0' || *p == '/') {
                break;
            }
            port[i] = *p;
            p++;
        }
        port[i] = '\0';
        *outPort = (uint16_t)atoi(port);
    }
    return 0;
}

static void my_readLine(char* src, char* dst, size_t dstlen) {
    if (src != NULL) {
        dstlen--;
        while (dstlen > 0) {
            if (*src == '\0' || *src == '\r') {
                break;
            }
            *dst = *src;
            src++;
            dst++;
            dstlen--;
        }
    }
    *dst = '\0';
}

typedef struct {
    pthread_t th;
    mSocket* s;
    uint32_t ip;
    uint16_t port;
} connectData_t;

static int32 my_connectSync(SOCKET_T s, int32 ip, uint16 port) {
    struct sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_port = htons(port);
    clientService.sin_addr.s_addr = htonl(ip);  //inet_addr("127.0.0.1");

    printf("my_connect('%s', %d)\n", inet_ntoa(clientService.sin_addr), port);

    if (connect(s, (struct sockaddr*)&clientService, sizeof(clientService)) != 0) {
        printf("my_connect(0x%X) fail\n", ip);
        return MR_FAILED;
    }
    printf("my_connect(0x%X) suc\n", ip);
    return MR_SUCCESS;
}

static void* my_connectAsync(void* arg) {
    connectData_t* data = (connectData_t*)arg;
    int32_t r = my_connectSync(data->s->s, data->ip, data->port);
    data->s->realState = r;
    if (!isCMWAP) {  // cmnet模式下保持相同的连接状态
        data->s->state = r;
    }
    free(data);
    return NULL;
}
/*
   MR_SUCCESS 成功
   MR_FAILED 失败
   MR_WAITING 使用异步方式进行连接，应用需要轮询该socket的状态以获知连接状况 

   IP地址,如果一个主机的IP地址为218.18.95.203，则值为218<<24 + 18<<16 + 95<<8 + 203= 0xda125fcb
*/
int32 my_connect(int32 s, int32 ip, uint16 port, int32 type) {
#ifdef NETWORK_SUPPORT
    uIntMap* obj = uIntMap_search(&sockets, (uint32_t)s);
    mSocket* data = (mSocket*)obj->data;
    if (ip == 0x0A0000AC) {        // 10.0.0.172 cmwap代理地址
        data->state = MR_SUCCESS;  // cmwap下设置一个伪状态
        return MR_SUCCESS;
    }
    printf("my_connect() type: %s\n", type == MR_SOCKET_BLOCK ? "block" : "async");
    if (type == MR_SOCKET_NONBLOCK) {
        connectData_t* d = malloc(sizeof(connectData_t));
        d->s = data;
        d->ip = ip;
        d->port = port;
        int ret = pthread_create(&d->th, NULL, my_connectAsync, d);
        if (ret != 0) {
            data->state = MR_FAILED;
            data->realState = MR_FAILED;
            return MR_FAILED;
        }
        return MR_WAITING;
    }
    return my_connectSync(data->s, ip, port);
#else
    return MR_FAILED;
#endif
}

/*
   MR_SUCCESS ： 连接成功
   MR_FAILED ： 连接失败
   MR_WAITING ： 连接中
   MR_IGNORE ： 不支持该功能
*/
int32 my_getSocketState(int32 s) {
#ifdef NETWORK_SUPPORT
    uIntMap* obj = uIntMap_search(&sockets, (uint32_t)s);
    mSocket* p = ((mSocket*)obj->data);
    printf("my_getSocketState(%d): %d\n", s, p->state);
    return p->state;
#else
    return MR_FAILED;
#endif
}

static int32_t socketCounter = 0;
/*
 >=0 返回的Socket句柄 
   MR_FAILED 失败 
*/
int32 my_socket(int32 type, int32 protocol) {
#ifdef NETWORK_SUPPORT
    type = (type == MR_SOCK_STREAM) ? SOCK_STREAM : SOCK_DGRAM;
    protocol = (protocol == MR_IPPROTO_TCP) ? IPPROTO_TCP : IPPROTO_UDP;
    SOCKET_T sock = socket(AF_INET, type, protocol);
    if (sock == -1) {
        printf("my_socket() fail\n");
        return MR_FAILED;
    }
    socketCounter++;

    mSocket* data = malloc(sizeof(mSocket));
    data->s = sock;
    data->realState = MR_WAITING;
    data->state = MR_WAITING;
    data->sendCounter = 0;

    uIntMap* obj = malloc(sizeof(uIntMap));
    obj->key = socketCounter;
    obj->data = (void*)data;
    uIntMap_insert(&sockets, obj);
    return socketCounter;
#else
    return MR_FAILED;
#endif
}

int32 my_closeSocket(int32 s) {
#ifdef NETWORK_SUPPORT
    uIntMap* obj = uIntMap_delete(&sockets, (uint32_t)s);
    if (obj == NULL) {
        return MR_FAILED;
    }
    mSocket* data = (mSocket*)obj->data;
    SOCKET_T sock = data->s;
    free(data);
    free(obj);
    shutdown(sock, SHUTDOWN_BIDIRECTIONAL);
    if (CLOSE_SOCKET(sock) != 0) {
        return MR_FAILED;
    }
    return MR_SUCCESS;
#else
    return MR_FAILED;
#endif
}

int32 my_closeNetwork(void) {
#ifdef NETWORK_SUPPORT
    struct rb_node* p;
    while ((p = rb_first(&sockets)) != NULL) {
        uIntMap* obj = rb_entry(p, uIntMap, node);
        my_closeSocket((int32)obj->key);
    }
#ifdef WIN_PLAT
    WSACleanup();
#endif
    return MR_SUCCESS;
#else
    return MR_FAILED;
#endif
}

typedef struct {
    MR_INIT_NETWORK_CB cb;
    void* userData;
    uc_engine* uc;
    pthread_t th;
} initNetworkAsyncData_t;

static int32 my_initNetworkSync() {
#ifdef WIN_PLAT
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return MR_FAILED;
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        printf("Could not find a usable version of Winsock.dll\n");
        my_closeNetwork();
        return MR_FAILED;
    }
#elif defined(__EMSCRIPTEN__) && defined(NETWORK_SUPPORT)
    bridgeSocket = emscripten_init_websocket_to_posix_socket_bridge("ws://127.0.0.1:8888/socket");
    // Synchronously wait until connection has been established.
    uint16_t readyState = 0;
    do {
        emscripten_websocket_get_ready_state(bridgeSocket, &readyState);
        emscripten_thread_sleep(100);
        printf("readyState:%d\n", readyState);
    } while (readyState == 0);
#endif
    return MR_SUCCESS;
}

static void* my_initNetworkAsync(void* arg) {
    initNetworkAsyncData_t* data = (initNetworkAsyncData_t*)arg;
    int32 r = my_initNetworkSync();
    printf("my_initNetworkAsync(): %d\n", r);
    bridge_dsm_network_cb(data->uc, (uint32_t)data->cb, r, (uint32_t)data->userData);
    free(data);
    return NULL;
}

/*  
   MR_SUCCESS 同步模式，初始化成功，不再调用cb
   MR_FAILED （立即感知的）失败，不再调用cb
   MR_WAITING 使用回调函数通知引擎初始化结果 
*/
int32 my_initNetwork(uc_engine* uc, MR_INIT_NETWORK_CB cb, const char* mode, void* userData) {
#ifdef NETWORK_SUPPORT
    printf("my_initNetwork(0x%p, '%s')\n", cb, mode);
    if (strncasecmp("cmwap", mode, 5) == 0) {
        isCMWAP = TRUE;
    }
    if (cb != NULL) {
        initNetworkAsyncData_t* data = malloc(sizeof(initNetworkAsyncData_t));
        data->cb = cb;
        data->userData = userData;
        data->uc = uc;
        if (pthread_create(&data->th, NULL, my_initNetworkAsync, data) != 0) {
            return MR_FAILED;
        }
        return MR_WAITING;
    }
    return my_initNetworkSync();
#else
    return MR_FAILED;
#endif
}

typedef struct {
    char* name;
    MR_GET_HOST_CB cb;
    void* userData;
    uc_engine* uc;
    pthread_t th;
} getHostByNameAsyncData_t;

static int32 my_getHostByNameSync(const char* name) {
    int32 ret = MR_FAILED;

#if 1
    struct addrinfo *result, *res;
    if (getaddrinfo(name, NULL, NULL, &result) != 0) {
        printf("getaddrinfo failed!\n");
        return ret;
    }
    for (res = result; res; res = res->ai_next) {
        if (res->ai_family == AF_INET) {
            struct in_addr* addr = &((struct sockaddr_in*)res->ai_addr)->sin_addr;
            // char addrstr[100];
            // printf("--- IPv4 address: %s\n", inet_ntop(res->ai_family, addr, addrstr, sizeof(addrstr)));
            printf("--- IPv4 address: %s\n", inet_ntoa(*addr));
            ret = ntohl((*addr).s_addr);
            break;
        }
    }
    freeaddrinfo(result);
#else
    struct hostent* remoteHost = gethostbyname(name);
    if (remoteHost != NULL) {
        if (remoteHost->h_addrtype == AF_INET) {
            if (remoteHost->h_addr_list[0] != NULL) {
                struct in_addr addr;
                addr.s_addr = *(u_long*)remoteHost->h_addr_list[0];
                printf("%s\n", inet_ntoa(addr));
                return ntohl(addr.s_addr);
            }
        }
    }
#endif
    return ret;
}

static void* my_getHostByNameAsync(void* arg) {
    getHostByNameAsyncData_t* data = (getHostByNameAsyncData_t*)arg;
    int32 r = my_getHostByNameSync(data->name);
    printf("my_getHostByNameAsync(): 0x%X\n", r);
    bridge_dsm_network_cb(data->uc, (uint32_t)data->cb, r, (uint32_t)data->userData);
    free(data->name);
    free(data);
    return NULL;
}

/*
   MR_FAILED （立即感知的）失败，不再调用cb
   MR_WAITING 使用回调函数通知引擎获取IP的结果
   其他值 同步模式，立即返回的IP地址，不再调用cb 
*/
int32 my_getHostByName(uc_engine* uc, const char* name, MR_GET_HOST_CB cb, void* userData) {
#ifdef NETWORK_SUPPORT
    printf("my_getHostByName('%s', 0x%p)\n", name, cb);
    if (cb != NULL) {
        getHostByNameAsyncData_t* data = malloc(sizeof(getHostByNameAsyncData_t));
        int len = strlen(name);
        data->name = malloc(len + 1);
        strcpy(data->name, name);
        data->name[len] = '\0';
        data->cb = cb;
        data->userData = userData;
        data->uc = uc;
        int ret = pthread_create(&data->th, NULL, my_getHostByNameAsync, data);
        if (ret != 0) {
            return MR_FAILED;
        }
        return MR_WAITING;
    }
    return my_getHostByNameSync(name);
#else
    return MR_FAILED;
#endif
}

// 返回-1表示失败，0表示不可写，1表示可写
int checkWritable(SOCKET_T socket) {
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(socket, &writefds);

    struct timeval timeout = {
        .tv_sec = 0,
        .tv_usec = 1000 * 50  // 50ms
    };

    SOCKET_T max_sd = socket;
    int ret = select(max_sd + 1, NULL, &writefds, NULL, &timeout);
    if (ret == 0) {  // timeout
        return 0;
    } else if (ret == -1) {
        return -1;
    }

    if (FD_ISSET(socket, &writefds)) {
        return 1;
    }
    return 0;
}

int32 my_sendto(int32 s, const char* buf, int len, int32 ip, uint16 port) {
#ifdef NETWORK_SUPPORT
    uIntMap* obj = uIntMap_search(&sockets, (uint32_t)s);
    mSocket* data = (mSocket*)obj->data;

    struct sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = htonl(ip);

    printf("my_sendto(len:%d, '%s:%d')\n", len, inet_ntoa(to.sin_addr), port);

    int ret = sendto(data->s, buf, len, 0, (struct sockaddr*)&to, sizeof(to));
    if (ret == -1) {
        return MR_FAILED;
    }
    return ret;
#else
    return MR_FAILED;
#endif
}

/*
   >=0 实际发送的数据字节个数
   MR_FAILED Socket已经被关闭或遇到了无法修复的错误。 
*/
int32 my_send(int32 s, const char* buf, int len) {
#ifdef NETWORK_SUPPORT
    uIntMap* obj = uIntMap_search(&sockets, (uint32_t)s);
    mSocket* data = (mSocket*)obj->data;

    data->sendCounter++;
    if (isCMWAP) {  // cmwap模式需要通过代理，这里模拟代理的功能
        if (data->realState == MR_WAITING) {
            if (data->sendCounter == 1) {  // 第一次发送数据，尝试连接
                char tmp[256];
                char host[256];
                uint16_t port;
                my_readLine((char*)buf, tmp, sizeof(tmp));
                if (parseHostPort(tmp, host, sizeof(host), &port) == MR_FAILED) {
                    return MR_FAILED;
                }
                int32 ip = my_getHostByNameSync(host);
                if (ip == MR_FAILED) {
                    return MR_FAILED;
                }
                if (my_connect(s, ip, port, MR_SOCKET_NONBLOCK) == MR_FAILED) {
                    return MR_FAILED;
                }
            }
            return 0;  // 还没连接上，因此返回0表示发送了0字节
        } else if (data->realState == MR_FAILED) {
            return MR_FAILED;
        }
    }
    int ret = checkWritable(data->s);
    if (ret == -1) {
        return MR_FAILED;
    } else if (ret == 0) {
        return 0;
    }
    ret = send(data->s, buf, len, 0);
    if (ret == -1) {
        return MR_FAILED;
    }
    return ret;
#else
    return MR_FAILED;
#endif
}

// 返回-1表示失败，0表示不可读，1表示可读
int checkReadable(SOCKET_T socket) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(socket, &readfds);

    struct timeval timeout = {
        .tv_sec = 0,
        .tv_usec = 1000 * 50  // 50ms
    };

    SOCKET_T max_sd = socket;
    int ret = select(max_sd + 1, &readfds, NULL, NULL, &timeout);
    if (ret == 0) {  // timeout
        return 0;
    } else if (ret == -1) {
        return -1;
    }
    if (FD_ISSET(socket, &readfds)) {
        return 1;
    }
    return 0;
}

int32 my_recvfrom(int32 s, char* buf, int len, int32* ip, uint16* port) {
#ifdef NETWORK_SUPPORT
    uIntMap* obj = uIntMap_search(&sockets, (uint32_t)s);
    mSocket* data = (mSocket*)obj->data;
    int ret = checkReadable(data->s);
    if (ret == -1) {
        return MR_FAILED;
    } else if (ret == 0) {
        return 0;
    }
    struct sockaddr_in from;
    int fromLen = sizeof(from);
    ret = recvfrom(data->s, buf, len, 0, (struct sockaddr*)&from, &fromLen);
    if (ret == -1) {
        return MR_FAILED;
    }

    if (from.sin_family != AF_INET) {
        printf("warning my_recvfrom() recv not ipv4\n");
    }
    *port = ntohs(from.sin_port);
    *ip = ntohl(from.sin_addr.s_addr);
    printf("my_recvfrom(len:%d, '%s:%d')\n", len, inet_ntoa(from.sin_addr), *port);

    return ret;
#else
    return MR_FAILED;
#endif
}

/*
   >=0的整数 实际接收的数据字节个数
   MR_FAILED Socket已经被关闭或遇到了无法修复的错误。 
*/
int32 my_recv(int32 s, char* buf, int len) {
#ifdef NETWORK_SUPPORT
    uIntMap* obj = uIntMap_search(&sockets, (uint32_t)s);
    mSocket* data = (mSocket*)obj->data;
    int ret = checkReadable(data->s);
    if (ret == -1) {
        return MR_FAILED;
    } else if (ret == 0) {
        return 0;
    }
    ret = recv(data->s, buf, len, 0);
    if (ret == -1) {
        return MR_FAILED;
    }
    return ret;
#else
    return MR_FAILED;
#endif
}
