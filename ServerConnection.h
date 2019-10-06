#ifndef SERVERCONNECTION_H_
#define SERVERCONNECTION_H_

#include "Common.h"
#include <string>
#include <vector>
#include "MemBuff.h"
#include "HttpHeader.h"

class ServerAcceptHandler;
class UpSession;

class ServerConnection
{
public:
	ServerConnection(
			ServerAcceptHandler& accept
			, evutil_socket_t fd
			, struct sockaddr *addr
			, int64_t addrlen
			, bool    use_proxy
			, SSL_CTX* ssl_ctx );

	virtual ~ServerConnection();

	int readcb(struct bufferevent *bev);
	int writecb(struct bufferevent *bev);
	int eventcb(struct bufferevent *bev, short events);

	virtual size_t write(
					const uint8_t *data,
			        size_t length);

	bool				IsSSL() { return (ssl_ctx_ != nullptr); }

	ServerAcceptHandler&				getAccept() { return accept_; }
	std::unique_ptr<UpSession>& getUpstream() { return upstream_; }

	void	changeTLS();

private:
	ServerAcceptHandler&   accept_;
	SSL_CTX*	ssl_ctx_;
	SSL*		ssl_;
	std::unique_ptr<UpSession>		upstream_;
	bool		connected_;
	struct bufferevent *bev_;
	std::string client_addr_;
	evutil_socket_t fd_;
};

#endif /* SERVERCONNECTION_H_ */
