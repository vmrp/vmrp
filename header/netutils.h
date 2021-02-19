#ifndef GOBJECT_EXAMPLE_NETUTILS_H_
#define GOBJECT_EXAMPLE_NETUTILS_H_
#define WIN32
#if defined (WIN32)
#include <winsock2.h>
#include<Ws2tcpip.h>
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#else
#include <netinet/in.h>
#include<arpa/inet.h>
#endif
#ifdef __cplusplus
extern "C"
{
#endif
const char *rtc_inet_ntop(int af, const void *src, char* dst, socklen_t size);
int rtc_inet_pton(int af, const char* src, void *dst);
#ifdef __cplusplus
}
#endif
#endif /* GOBJECT_EXAMPLE_NETUTILS_H_ */