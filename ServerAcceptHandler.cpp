#include "ServerAcceptHandler.h"
#include "EventHandler.h"
#include "ServerConnection.h"

void ServerAcceptHandler::termSocket()
{
#ifdef _WIN32
	WSACleanup();
#endif
}

static void* startServer(void *p)
{
	ServerAcceptHandler *serverHandler = (ServerAcceptHandler *)p;
	serverHandler->start_listen();
	pthread_exit(NULL);

	return NULL;
}

void ServerAcceptHandler::start()
{
	int ret = pthread_create(&thread_, NULL, startServer, (void *)this);
	if (ret != 0)
	{
		errx(1, "can not create thread : %s", strerror(ret));
	}
	else
	{
		dothread_ = true;
	}
}

void ServerAcceptHandler::stop()
{
	event_.stop();
}


static void acceptcb(
		struct evconnlistener *listener, evutil_socket_t fd,
        struct sockaddr *addr, int addrlen, void *arg)
{
	ServerAcceptHandler* acceptHandler = static_cast<ServerAcceptHandler *>(arg);
	acceptHandler->accept(listener,fd, addr, addrlen);
}

static void timercb(
	evutil_socket_t fd,
	short events, 
	void * arg)
{
	ServerAcceptHandler* acceptHandler = static_cast<ServerAcceptHandler *>(arg);
	acceptHandler->stop();
}

ServerAcceptHandler::ServerAcceptHandler(SettingConnection& setting)
	: dothread_(false)
	, thread_()
	, event_()
	, setting_(setting)
	, ssl_ctx_(nullptr)
	, ssl_socket_(0)
	, connections_()
	, response_rule_()
	, response_mutex(PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP)
	, timerev_(nullptr)
	, listeners_()
{
	timerev_ = evtimer_new(
					event_.getEventBase(), timercb, this );

	if (setting_.enable_tls)
	{
		if (setting_.ssl_ctx != nullptr)
		{
			ssl_ctx_ = setting_.ssl_ctx;
		}
		else
		{
			ssl_ctx_ = setup_default_tls();
		}
	}
}

ServerAcceptHandler::~ServerAcceptHandler()
{

	auto itr = listeners_.begin();
	while (itr != listeners_.end())
	{
		evconnlistener_free((*itr));
		itr = listeners_.erase(itr);
	}


	stop();

	if (ssl_ctx_ != setting_.ssl_ctx)
	{
		SSL_CTX_free(ssl_ctx_);
		ssl_ctx_ = nullptr;
	}

	if (dothread_ == false)
	{
		return;
	}

	int ret = pthread_join(thread_, NULL);
	if (ret != 0)
	{
		errx(1, "can not join thread %d", ret);
	}
}

static void die_most_horribly_from_openssl_error(const char *func)
{
	warnx("%s failed:\n", func);

	/* This is the OpenSSL function that prints the contents of the
	 * error stack to the specified file handle. */
	ERR_print_errors_fp(stderr);

//	exit(EXIT_FAILURE);
}

SSL_CTX * ServerAcceptHandler::setup_default_tls()
{
	SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_server_method());

	//SSL_CTX_set_options(ctx,
	//	SSL_OP_SINGLE_DH_USE |
	//	SSL_OP_SINGLE_ECDH_USE |
	//	SSL_OP_NO_SSLv2);

	/* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
	 * We just hardcode a single curve which is reasonably decent.
	 * See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
	//EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	//if (!ecdh)
	//{ 
	//	die_most_horribly_from_openssl_error("EC_KEY_new_by_curve_name");
	//	SSL_CTX_free(ctx);
	//	return nullptr;
	//}

	//if (1 != SSL_CTX_set_tmp_ecdh(ctx, ecdh))
	//{ 
	//	die_most_horribly_from_openssl_error("SSL_CTX_set_tmp_ecdh");
	//	SSL_CTX_free(ctx);
	//	return nullptr;
	//}


//	const char *certificate_chain = "server_crt.pem";
//	const char *private_key = "server_privatekey.pem";
	server_setup_certs (
		ctx, 
		setting_.certificate_chain.c_str(),
		setting_.private_key.c_str() );

	return ctx;
}

int32_t ServerAcceptHandler::server_setup_certs(
				SSL_CTX *ctx,
				const char *certificate_chain,
				const char *private_key)
{
	warnx("Loading certificate chain from '%s'\n"
		"and private key from '%s'\n",
		certificate_chain, private_key);

	if (1 != SSL_CTX_use_certificate_chain_file(ctx, certificate_chain))
	{
		die_most_horribly_from_openssl_error("SSL_CTX_use_certificate_chain_file");
		return -1;
	}

	if (1 != SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM))
	{
		die_most_horribly_from_openssl_error("SSL_CTX_use_PrivateKey_file");
		return -1;
	}


	if (1 != SSL_CTX_check_private_key(ctx))
	{
		die_most_horribly_from_openssl_error("SSL_CTX_check_private_key");
		return -1;
	}

	return 0;

}



void ServerAcceptHandler::start_listen()
{
	struct evconnlistener* listener = nullptr;

	listener = bind_port(
		setting_.node.c_str(),
		setting_.port_http.c_str());
	if (listener != nullptr)
	{
		listeners_.push_back(listener);

		warnx("http server start node:%s port:%s",
			setting_.node.c_str(), setting_.port_http.c_str() );

	}
	else
	{
		warnx("Error: Can't http server start node:%s port:%s", 
			setting_.node.c_str(), setting_.port_http.c_str());
	}

	if (setting_.enable_tls)
	{
		listener = bind_port(
			setting_.node.c_str(),
			setting_.port_https.c_str());
		if (listener != nullptr)
		{
			ssl_socket_ = evconnlistener_get_fd(listener);
			listeners_.push_back(listener);

			warnx("https server start node:%s port:%s(%d)",
				setting_.node.c_str(), setting_.port_https.c_str(), ssl_socket_);

		}
		else
		{
			warnx("Error: Can't https server start node:%s port:%s",
				setting_.node.c_str(), setting_.port_https.c_str());
		}
	}


	if(listeners_.size() > 0)
	{
		event_.loop();
	}
	else
	{
		errx(1, "Could not start no listener");
	}

	warnx("stop server");
}

struct evconnlistener* ServerAcceptHandler::bind_port(
	const char*	node,
	const char* service)
{

	struct event_base *evbase = event_.getEventBase();
	int rv;
	struct addrinfo hints;
	struct addrinfo *res, *rp;
	struct evconnlistener *listener = nullptr;


	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

	rv = getaddrinfo(node, service, &hints, &res);
	if (rv != 0) 
	{
		errx(1, "Could not resolve server address node:%s service:%s", node, service);
		return nullptr;
	}
	
	for (rp = res; rp; rp = rp->ai_next)
	{
		listener = evconnlistener_new_bind(
			evbase, acceptcb, this,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 16, rp->ai_addr,
			(int)rp->ai_addrlen);
		
		if (listener)
		{
			freeaddrinfo(res);
			break;
		}

		listener = nullptr;
	}

	return listener;
}

void ServerAcceptHandler::accept(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int64_t addrlen)
{
	warnx("accept %d",fd);


	if (evtimer_pending(timerev_,NULL) != 0)
	{
		evtimer_del(timerev_);
	}


	switchthread();
	ServerConnection*   serverCon = nullptr;
	
	evutil_socket_t accept_fd = evconnlistener_get_fd(listener);
	if (ssl_socket_ == accept_fd)
	{
		serverCon = new ServerConnection(*this, fd, addr, addrlen, setting_.use_proxymode, ssl_ctx_);
	}
	else
	{
		serverCon = new ServerConnection(*this, fd, addr, addrlen, setting_.use_proxymode, nullptr);
	}
	
	connections_.push_back(std::unique_ptr<ServerConnection>(serverCon));


	return;
}

void ServerAcceptHandler::removeSocket(
				ServerConnection* server)
{
	for(auto it = connections_.begin(); it != connections_.end(); it++)
	{
		auto& checkclient = *it;

		if(checkclient.get() == server)
		{
			it = connections_.erase(it);
			break;
		}
	}

	if (connections_.size() <= 0)
	{
		if (setting_.exit_time.tv_sec == 0 &&
			setting_.exit_time.tv_usec == 0)
		{
			stop();
		}
		else
		{
			evtimer_add(timerev_, &setting_.exit_time);
		}
	}
}


void ServerAcceptHandler::addResponse(
	ResponseRulePtr response)
{
	pthread_mutex_lock(&response_mutex);

	response_rule_.push_back(response);

	pthread_mutex_unlock(&response_mutex);
}

ResponseRulePtr ServerAcceptHandler::popResponse(
						HttpRequest&     req)
{
	ResponseRulePtr rule;
	pthread_mutex_lock(&response_mutex);

	auto itr = response_rule_.begin();
	while (itr != response_rule_.end())
	{
		ResponseRulePtr& cur_rule = *itr;
		if (cur_rule->IsMatch(req) == true)
		{
			rule = cur_rule;
			if(cur_rule->IsDeleteRule() == true)
			{
				itr = response_rule_.erase(itr);
			}
			break;
		}
		else
		{
			itr++;
		}
	}
	pthread_mutex_unlock(&response_mutex);
	return rule;
}
