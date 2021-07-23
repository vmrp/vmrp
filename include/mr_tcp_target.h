#ifndef MR_TCP_H
#define MR_TCP_H
/*=========================================================================*\
* TCP object
* LuaSocket toolkit
*
* The tcp.h module is basicly a glue that puts together modules buffer.h,
* timeout.h socket.h and inet.h to provide the LuaSocket TCP (AF_INET,
* SOCK_STREAM) support.
*
* Three classes are defined: master, client and server. The master class is
* a newly created tcp object, that has not been bound or connected. Server
* objects are tcp objects bound to some local address. Client objects are
* tcp objects either connected to some address or returned by the accept
* method of a server object.
*
* RCS ID: $Id: tcp.h,v 1.5 2004/02/04 14:29:10 diego Exp $
\*=========================================================================*/
#include "mr.h"
#include "mr_socket_target.h"
//#include "buffer.h"
//#include "timeout.h"
//#include "socket.h"



//typedef int socklen_t;
typedef int32 t_sock;

/* Socket State */
enum {
   MRSOCK_OPENED = 0,        
   MRSOCK_CONNECTING ,        
   MRSOCK_CONNECTED ,
   MRSOCK_CLOSED ,        
   MRSOCK_TIMEOUT ,
   MRSOCK_ERR
};

#define BUF_SIZE 1500
typedef struct t_tcp_ {
    t_sock sock;
    char buf[BUF_SIZE];    /* storage space for buffer data */
    int state;
    size_t sent, received;  /* bytes sent, and bytes received */
//    t_tm tm;
} t_tcp;

typedef t_tcp *p_tcp;



extern int mr_tcp_open(mrp_State *L);
extern int mr_udp_open(mrp_State *L);

#endif /* TCP_H */
