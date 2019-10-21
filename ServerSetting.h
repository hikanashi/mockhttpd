#ifndef SERVERSETTING_H_
#define SERVERSETTING_H_

#include "Common.h"
#include "HttpHeader.h"
#include <string>


typedef struct _SettingConnection
{
	std::string port_http;
	std::string port_https;
	std::string node;
	bool		enable_tls;
	bool		use_proxymode;
	SSL_CTX*	ssl_ctx;
	std::string certificate_chain;
	std::string private_key;

	bool		enable_clientverify;
	intptr_t	verify_depth;
	std::string	client_certificate;

	struct timeval exit_time; // sec, usec

	_SettingConnection()
		: port_http(std::string("80"))
		, port_https(std::string("443"))
		, node(std::string("127.0.0.1"))
		, enable_tls(true)
		, use_proxymode(false)
		, ssl_ctx(nullptr)
		, certificate_chain("/opt/local/SSL/svr1CA.pem")
		, private_key("/opt/local/SSL/svr1key.pem")
		, enable_clientverify(false)
		, verify_depth(3)
		, client_certificate("/opt/local/SSL/rootCA.pem")
		, exit_time()
	{}
	_SettingConnection(const char* httpport, const char* httpsport, const char* node)
		: port_http(std::string(httpport))
		, port_https(std::string(httpsport))
		, node(std::string(node))
		, enable_tls(true)
		, use_proxymode(false)
		, ssl_ctx(nullptr)
		, certificate_chain("/opt/local/SSL/svr1CA.pem")
		, private_key("/opt/local/SSL/svr1key.pem")
		, enable_clientverify(false)
		, verify_depth(3)
		, client_certificate("/opt/local/SSL/rootCA.pem")
		, exit_time()
	{}
} SettingConnection;


#endif