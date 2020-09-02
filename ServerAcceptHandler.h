#ifndef SERVERACCEPTHANDLER_H_
#define SERVERACCEPTHANDLER_H_

#include "Common.h"
#include <string>
#include <vector>
#include <stdio.h>
#include <sys/types.h>
#include <memory>

#ifndef HAVE_STRUCT_TIMESPEC
#define HAVE_STRUCT_TIMESPEC
#endif
#include <thread>
#include <mutex>

#include "EventHandler.h"
#include "ServerSetting.h"
#include "ResponseRule.h"

#include "OpenSSLTypes.h"


class ServerConnection;
class OcspClient;

class ServerAcceptHandler
{
public:
	ServerAcceptHandler(SettingConnection& setting);
	virtual ~ServerAcceptHandler();

	void start();
	void stop();
	static void termSocket();

	bool isRunning() const;

	const SettingConnection& getSetting() const{ return setting_;}

	void start_listen();
	void accept(
		struct evconnlistener *listener,
		evutil_socket_t fd, 
		struct sockaddr *addr,
		int64_t addrlen);

	EventHandler& getEv() { return event_; }
	void removeSocket(
					ServerConnection* server);

	void addResponse(
				ResponseRulePtr response);

	ResponseRulePtr popResponse(
				HttpRequest&     req);

protected:
	struct evconnlistener* bind_port(
		const char*	node,
		const char* service);

	SSL_CTX * setup_default_tls();

	int32_t setup_server_certs(
		SSL_CTX *ctx,
		const char *certificate_chain,
		const char *private_key,
		openssl::UniquePtr<X509>& cert);

	void load_certchain(
		const char*	cert_path,
		SSL_CTX *ctx,
		openssl::UniquePtr<X509>& cert);

	int32_t setup_client_certs(
		SSL_CTX *ctx,
		std::string& cert,
		intptr_t depth);

	int32_t setup_ocsp_stapling(
		SSL_CTX*	ctx,
		X509*		cert);


private:
	std::thread thread_;
	bool	is_runnning_;
	EventHandler  event_;
	SettingConnection setting_;
	SSL_CTX*	ssl_ctx_;
	evutil_socket_t     ssl_socket_;

	std::vector<std::unique_ptr<ServerConnection> > connections_;

	std::vector< ResponseRulePtr > response_rule_;
	std::recursive_mutex response_mutex_;
	struct event*	timerev_;
	std::vector<struct evconnlistener*> listeners_;

	openssl::UniquePtr<SSL_CTX>	default_ssl_ctx_;
	openssl::UniquePtr<X509>	cert_;
	std::shared_ptr<OcspClient>	ocsp_;

};

#endif /* SERVERACCEPTHANDLER_H_ */
