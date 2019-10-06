#ifndef UPSESSION_H_
#define UPSESSION_H_

#include "Common.h"
#include "HttpHeader.h"

class ServerConnection;

class UpSession
{
public:
	UpSession(ServerConnection& handler);
	virtual ~UpSession();
	virtual ssize_t on_read(unsigned char *data, size_t datalen) = 0;
	virtual ssize_t on_write() = 0;
	virtual ssize_t on_event() = 0;
	virtual ssize_t DoFlush() = 0;
	virtual ssize_t send(
					HttpMessagePtr&	message) = 0;

protected:
	int parseAuthority(const char* authority,
					size_t		authoritylen,
					std::string& host,
					uint16_t&	port);

	int parseURI(const char* uri,
				size_t		urilen,
				std::string& schema,
				std::string& host,
				uint16_t&	port,
				std::string& path);

protected:
	ServerConnection &handler_;
};

#endif /* UPSTREAM_H_ */
