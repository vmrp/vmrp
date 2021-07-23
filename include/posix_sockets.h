#ifndef __POSIX_SOCKETS_H__
#define __POSIX_SOCKETS_H__

#include <stdio.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)

#define WIN_PLAT
// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#define SOCKET_T SOCKET
#define SHUTDOWN_READ SD_RECEIVE
#define SHUTDOWN_WRITE SD_SEND
#define SHUTDOWN_BIDIRECTIONAL SD_BOTH
#define SETSOCKOPT_PTR_TYPE const char *
#define SEND_RET_TYPE int
#define SEND_FORMATTING_SPECIFIER "%d"
#define CLOSE_SOCKET(x) closesocket(x)

#define GET_SOCKET_ERROR() (WSAGetLastError())

static inline void PRINT_SOCKET_ERROR(int errorCode) {
    void *lpMsgBuf = 0;
    HRESULT hresult = HRESULT_FROM_WIN32(errorCode);
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  0, hresult, 0 /*Default language*/, (LPTSTR)&lpMsgBuf, 0, 0);
    printf("Call failed! WSAGetLastError: %s(%d)\n", (char *)lpMsgBuf, errorCode);
    LocalFree(lpMsgBuf);
}

#else

#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/tcp.h>

#define SOCKET_T int
#define SHUTDOWN_READ SHUT_RD
#define SHUTDOWN_WRITE SHUT_WR
#define SHUTDOWN_BIDIRECTIONAL SHUT_RDWR
#define SETSOCKOPT_PTR_TYPE const int *
#define SEND_RET_TYPE ssize_t
#define SEND_FORMATTING_SPECIFIER "%ld"
#define CLOSE_SOCKET(x) close(x)

#define GET_SOCKET_ERROR() (errno)

#define PRINT_SOCKET_ERROR(errorCode)                                           \
    do {                                                                        \
        printf("Call failed! errno: %s(%d)\n", strerror(errorCode), errorCode); \
    } while (0)

#endif

#endif
