#ifndef COMMON_H_
#define COMMON_H_

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 
#endif

#ifdef __RELATIVE_FILE_PATH__
#define __FILE__ __RELATIVE_FILE_PATH__
#endif

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
		printf("%s#%d\n", __FILE__, __LINE__);	\
		printf(__VA_ARGS__);	\
		printf("\n");			\
	} while (0);
#define errx(flg,...)			\
	do {						\
		printf("--mockhttpd- ");	\
		printf("%s#%d", __FILE__, __LINE__);	\
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
		nanosleep(&to,NULL);		\
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
