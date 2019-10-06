#ifndef UPSESSIONHTTP_H_
#define UPSESSIONHTTP_H_

#include "Common.h"
#include "http-parser/http_parser.h"
#include "UpSession.h"
#include "SessionHttp1Handler.h"
#include "ServerSetting.h"

class ServerConnection;

class UpSessionHttp : public UpSession,
					  public SessionHttp1Handler
{
public:
	UpSessionHttp(ServerConnection& handler);
	virtual ~UpSessionHttp();

	virtual ssize_t on_read(unsigned char *data, size_t datalen);
	virtual ssize_t on_write();
	virtual ssize_t on_event();
	virtual ssize_t DoFlush();

	virtual ssize_t send(
			HttpMessagePtr&	message);


	int htp_msg_begin(http_parser *htp);
	int htp_uricb(http_parser *htp, const char *data, size_t len);
	int htp_hdr_keycb(http_parser *htp, const char *data, size_t len);
	int htp_hdr_valcb(http_parser *htp, const char *data, size_t len);
	int htp_hdrs_completecb(http_parser *htp);
	int htp_bodycb(http_parser *htp, const char *data, size_t len);
	int htp_msg_completecb(http_parser *htp);

	HttpMessagePtr&	getRequest() { return request_; }

protected:
	void setDefaultResponse(
				HttpResponse* res);
	size_t sendConnectResult();

private:
	HttpHeaderField curheader_;
	HttpMessagePtr request_;

};


#endif /* UPSESSIONHTTP_H_ */
