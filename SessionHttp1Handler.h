#ifndef SESSIONHTTP1HANDLER_H_
#define SESSIONHTTP1HANDLER_H_

#include "Common.h"
#include "http-parser/http_parser.h"

class SessionHttp1Handler
{
public:
	SessionHttp1Handler(enum http_parser_type type);
	virtual ~SessionHttp1Handler();


	virtual int htp_msg_begin(http_parser *htp) = 0;
	virtual int htp_uricb(http_parser *htp, const char *data, size_t len);
	virtual int htp_statuscb(http_parser *htp, const char *data, size_t len);
	virtual int htp_hdr_keycb(http_parser *htp, const char *data, size_t len);
	virtual int htp_hdr_valcb(http_parser *htp, const char *data, size_t len);
	virtual int htp_hdrs_completecb(http_parser *htp);
	virtual int htp_bodycb(http_parser *htp, const char *data, size_t len);
	virtual int htp_msg_completecb(http_parser *htp);

protected:
	int recv(unsigned char *data, size_t datalen);

protected:
	std::unique_ptr<http_parser> htp_;
};

#endif /* SESSIONHTTP1HANDLER_H_ */
