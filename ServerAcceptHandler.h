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
#include <pthread.h>

#include "ServerAcceptHandler.h"
#include "EventHandler.h"
#include "ServerSetting.h"
#include "ResponseRule.h"



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
		X509**		cert);

	X509* load_certchain(
		const char*	cert_path,
		SSL_CTX *ctx);

	int32_t setup_client_certs(
		SSL_CTX *ctx,
		std::string& cert,
		intptr_t depth);

	int32_t setup_ocsp_stapling(
		SSL_CTX*	ctx,
		X509*		cert);


private:
	bool	dothread_;
	pthread_t thread_;
	EventHandler  event_;
	SettingConnection setting_;
	SSL_CTX*	ssl_ctx_;
	evutil_socket_t     ssl_socket_;

	std::vector<std::unique_ptr<ServerConnection> > connections_;

	std::vector< ResponseRulePtr > response_rule_;
	pthread_mutex_t  response_mutex;
	struct event*	timerev_;
	std::vector<struct evconnlistener*> listeners_;

	X509*						cert_;
	std::shared_ptr<OcspClient>	ocsp_;

};

#endif /* SERVERACCEPTHANDLER_H_ */
