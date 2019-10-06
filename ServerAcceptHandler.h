#ifndef SERVERACCEPTHANDLER_H_
#define SERVERACCEPTHANDLER_H_

#include "Common.h"
#include <string>
#include <vector>
#include <stdio.h>
#include <sys/types.h>

#ifndef HAVE_STRUCT_TIMESPEC
#define HAVE_STRUCT_TIMESPEC
#endif
#include <pthread.h>

#include "ServerAcceptHandler.h"
#include "EventHandler.h"
#include "ServerSetting.h"
#include "ResponseRule.h"



class ServerConnection;

class ServerAcceptHandler
{
public:
	ServerAcceptHandler(SettingConnection& setting);
	virtual ~ServerAcceptHandler();

	void start();
	void stop();
	static void termSocket();


	void start_listen();
	void accept(evutil_socket_t fd, struct sockaddr *addr, int64_t addrlen);

	EventHandler& getEv() { return event_; }
	void removeSocket(
					ServerConnection* server);

	void addResponse(
				ResponseRulePtr response);

	ResponseRulePtr popResponse(
				HttpRequest&     req);

protected:
	SSL_CTX * setup_default_tls();

	int32_t server_setup_certs(
		SSL_CTX *ctx,
		const char *certificate_chain,
		const char *private_key);

private:
	bool	dothread_;
	pthread_t thread_;
	EventHandler  event_;
	SettingConnection setting_;
	SSL_CTX*	ssl_ctx_;

	std::vector<std::unique_ptr<ServerConnection> > connections_;

	std::vector< ResponseRulePtr > response_rule_;
	pthread_mutex_t  response_mutex;
	struct event*	timerev_;
	

};

#endif /* SERVERACCEPTHANDLER_H_ */
