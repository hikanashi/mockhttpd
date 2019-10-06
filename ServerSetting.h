#ifndef SERVERSETTING_H_
#define SERVERSETTING_H_

#include "Common.h"
#include "HttpHeader.h"
#include <string>


typedef struct _SettingConnection
{
	std::string port;
	bool		enable_tls;
	bool		use_proxymode;
	SSL_CTX*	ssl_ctx;
	std::string certificate_chain;
	std::string private_key;
	struct timeval exit_time; // sec, usec

	_SettingConnection()
		: port(std::string("80"))
		, enable_tls(false)
		, use_proxymode(false)
		, ssl_ctx(nullptr)
		, certificate_chain()
		, private_key()
		, exit_time()
	{}
	_SettingConnection(const char* port)
		: port(std::string(port))
		, enable_tls(false)
		, use_proxymode(false)
		, ssl_ctx(nullptr)
		, certificate_chain()
		, private_key()
		, exit_time()
	{}
} SettingConnection;


#endif