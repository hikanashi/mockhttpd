#include "ServerConnection.h"

#include <sys/types.h>
#include <string>
#include <sstream>

#include "EventHandler.h"
#include "util.h"
#include "UpSessionHttp.h"
#include "ServerAcceptHandler.h"

static void server_readcb(struct bufferevent *bev, void *ptr)
{
	switchthread();
	ServerConnection* serverCon = static_cast<ServerConnection *>(ptr);
	int rv = serverCon->readcb(bev);
	if( rv < 0 )
	{
		ServerAcceptHandler& accept = serverCon->getAccept();
		accept.removeSocket(serverCon);
	}
}

static void server_writecb(struct bufferevent *bev, void *ptr)
{
	switchthread();
	ServerConnection* serverCon = static_cast<ServerConnection *>(ptr);
	int rv = serverCon->writecb(bev);
	if( rv < 0 )
	{
		ServerAcceptHandler& accept = serverCon->getAccept();
		accept.removeSocket(serverCon);
	}
}

/* eventcb for bufferevent */
static void server_eventcb(struct bufferevent *bev, short events, void *ptr)
{
	switchthread();
	ServerConnection* serverCon = static_cast<ServerConnection *>(ptr);
	int rv = serverCon->eventcb(bev,events);
	if( rv < 0 )
	{
		ServerAcceptHandler& accept = serverCon->getAccept();
		accept.removeSocket(serverCon);
	}
}

ServerConnection::ServerConnection(
		ServerAcceptHandler& accept
		, evutil_socket_t fd
		, struct sockaddr *addr
		, int64_t addrlen
		, bool    use_proxy
		, SSL_CTX* ssl_ctx)
	: accept_(accept)
	, ssl_ctx_(ssl_ctx)
	, ssl_(nullptr)
	, upstream_(nullptr)
	, connected_(true)
	, bev_(nullptr)
	, client_addr_()
	, fd_(fd)
{

	int val = 1;
	setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));

	if (use_proxy == false && ssl_ctx_ != nullptr)
	{
		ssl_ = SSL_new(ssl_ctx_);

		bev_ = bufferevent_openssl_socket_new(
					accept_.getEv().getEventBase(),
					fd_,
					ssl_,
					BUFFEREVENT_SSL_ACCEPTING,
					BEV_OPT_CLOSE_ON_FREE);
	}
	else
	{ 
		bev_ = bufferevent_socket_new(
			accept_.getEv().getEventBase(), fd_,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS  );
	}

	bufferevent_enable(bev_, EV_READ | EV_WRITE);

	char host[NI_MAXHOST];
	int rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
				   NI_NUMERICHOST);
	if (rv != 0)
	{
		client_addr_ = "(unknown)";
	}
	else
	{
		client_addr_ = host;
	}

	upstream_ = std::unique_ptr<UpSession>(new UpSessionHttp(*this));
	warnx("ServerConnection %d %s create\n", fd, client_addr_.c_str());

	bufferevent_setcb(bev_, server_readcb, server_writecb, server_eventcb, this);

}

ServerConnection::~ServerConnection()
{

	warnx("ServerConnection %s delete start\n", client_addr_.c_str());
	connected_ = false;
	bufferevent_flush(bev_,EV_WRITE, BEV_FLUSH  );
	bufferevent_flush(bev_,EV_READ, BEV_FINISHED );

	bufferevent_free(bev_);
	warnx("ServerConnection %s delete end\n", client_addr_.c_str());
	//ssl is auto free(BEV_OPT_CLOSE_ON_FREE)
	//if (ssl_ != nullptr)
	//{
	//	SSL_free(ssl_);
	//	ssl_ = nullptr;
	//}
}

void ServerConnection::changeTLS()
{
	if (ssl_ctx_ == nullptr)
	{
		return;
	}

	if (ssl_ != nullptr)
	{
		return;
	}

	warnx("change TLS");

	ssl_ = SSL_new(ssl_ctx_);

	bev_ = bufferevent_openssl_filter_new(
			accept_.getEv().getEventBase(),
				bev_,
				ssl_,
				BUFFEREVENT_SSL_ACCEPTING,
				BEV_OPT_CLOSE_ON_FREE);

	bufferevent_enable(bev_, EV_READ | EV_WRITE);
	bufferevent_setcb(bev_, server_readcb, server_writecb, server_eventcb, this);

}

size_t ServerConnection::write(
				const uint8_t *data,
		        size_t length)
{
	switchthread();

	if( connected_ == false)
	{
		return 0;
	}

	size_t remain = length;
	const uint8_t* buff = data;

	while (remain > 0)
	{
		size_t size = SENDPART_MAX;
		if (size > remain)
		{
			size = remain;
		}

		int writeret = bufferevent_write(bev_, buff, size);
		warnx("<<<<<< SERVER send len=%d ret=%d", size, writeret);
		util::dumpbinary(buff, size);

		buff += size;
		remain -= size;

		switchthread();
	}

	return length;
}

size_t ServerConnection::write(
		std::stringstream& sendbuf)
{
	std::string buffer = sendbuf.str();
	size_t length = write((uint8_t*)buffer.c_str(), buffer.size());
	warnx("SERVER send:%s", buffer.c_str());

	sendbuf.str(""); // clear buffer
	sendbuf.clear(std::stringstream::goodbit); // clear statusbit
	return length;
}


int ServerConnection::readcb(struct bufferevent *bev)
{
	if(connected_ == false)
	{
		return 0;
	}

	if (ssl_ != nullptr &&
		accept_.getSetting().enable_clientverify != false)
	{

		X509* clientcert = SSL_get_peer_certificate(ssl_);
		if (clientcert == NULL)
		{
			warnx("client certificate no receive");
			return -1;
		}

		long client_verify = SSL_get_verify_result(ssl_);
		if (client_verify != X509_V_OK)
		{
			warnx("client verify error %d see DIAGNOSTICS from https://www.openssl.org/docs/man1.1.1/man1/verify.html ", client_verify);
			return -1;
		}
	}
	ssize_t readlen = 0;
	struct evbuffer* input = bufferevent_get_input(bev_);
	size_t datalen = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, -1);

	warnx(">>>>>>>> ServerConnection::readcb(start size: %lu) >>>>>>>>",datalen);
//	warnx("%30.30s",data);
//	warnx("%s",data);
	util::dumpbinary(data,datalen);


	if( upstream_ != nullptr)
	{
		readlen = upstream_->on_read(data,datalen);
	}

	if (readlen >= 0)
	{
		datalen = static_cast<size_t>(readlen);
		readlen = 0;
	}
		
	if (evbuffer_drain(input, datalen) != 0)
	{
		warnx("Fatal error: evbuffer_drain failed");
		return -1;
	}


	return static_cast<int>(readlen);
}


int ServerConnection::writecb(struct bufferevent *bev)
{
//	warnx("===============writecb==================");

	if (evbuffer_get_length(bufferevent_get_output(bev)) > 0)
	{
//		return -1;
	}

	return 0;
}

int ServerConnection::eventcb(struct bufferevent *bev, short events)
{
	if (events & BEV_EVENT_CONNECTED)
	{
		(void) bev;

		warnx("%s connected\n", client_addr_.c_str());

		return 0;
	}

	if (events & BEV_EVENT_EOF)
	{
		warnx("%s EOF\n", client_addr_.c_str());
	}
	else if (events & BEV_EVENT_ERROR)
	{
		int sockerr = EVUTIL_SOCKET_ERROR();
		warnx("sock error %d(%s)", 
			sockerr,
			evutil_socket_error_to_string(sockerr));
		warnx("%s network error\n", client_addr_.c_str());
	}
	else if (events & BEV_EVENT_TIMEOUT)
	{
		warnx("%s timeout\n", client_addr_.c_str());
	}

	return -1;
}
