#ifndef COMMON_H_
#define COMMON_H_

#include <stdint.h>
#include <memory>
#include <utility>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#define switchthread()				\
	do {							\
		std::this_thread::yield();	\
	} while (0);

#define warnx(...)	\
	do {						\
		printf("--mockhttpd- ");	\
		printf(__VA_ARGS__);	\
		printf("\n");			\
	} while (0);
#define errx(flg,...)			\
	do {						\
		printf("--mockhttpd- ");	\
		printf(__VA_ARGS__);	\
		printf("\n");			\
	} while (0);

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#else
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <direct.h>
#include <stdlib.h>
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#define getcwd _getcwd
#define putenv _putenv
#define stat _stat
typedef int64_t ssize_t;
#endif

#ifndef _WIN32
#define WAITMS(ms)			\
	do {						\
		switchthread();			\
		if(ms <= 0 ) break;		\
		struct timespec to;		\
		to.tv_sec = ms / 1000;	\
		to.tv_nsec = (ms - (to.tv_sec * 1000)) * 1000;	\
		nanosleep(ms,NULL);		\
	} while (0);
#else
#define WAITMS(ms)			\
	do {						\
		switchthread();			\
		if(ms <= 0 ) break;		\
		Sleep((DWORD)ms);				\
	} while (0);
#endif



typedef enum ConnectionProtocol
{
	ConnectionProtocol_PLANE = 0,
	ConnectionProtocol_HTTP1,
} ConnectionProtocol;


#endif /* COMMON_H_ */
