#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "type.h"
#include "mrporting.h"
#include "bridge.h"

int32 my_closeNetwork(void);
int32 my_initNetwork(_MR_INIT_NETWORK_CB cb, const char *mode, void *userData);
int32 my_getHostByName(const char *name, _MR_GET_HOST_CB cb, void *userData);
int32 my_socket(int32 type, int32 protocol);
int32 my_closeSocket(int32 s);
int32 my_sendto(int32 s, const char *buf, int len, int32 ip, uint16 port);
int32 my_send(int32 s, const char *buf, int len);
int32 my_recvfrom(int32 s, char *buf, int len, int32 *ip, uint16 *port);
int32 my_recv(int32 s, char *buf, int len);
int32 my_connect(int32 s, int32 ip, uint16 port, int32 type);
int32 my_getSocketState(int32 s);

#endif
