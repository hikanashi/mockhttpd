#include "SessionHttp1Handler.h"

namespace {
int htp_msg_begin(http_parser *htp)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_msg_begin(htp);
}

int htp_uricb(http_parser *htp, const char *data, size_t len)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_uricb(htp,data,len);
}

int htp_statuscb(http_parser *htp, const char *data, size_t len)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_statuscb(htp,data,len);
}

int htp_hdr_keycb(http_parser *htp, const char *data, size_t len)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_hdr_keycb(htp,data,len);
}

int htp_hdr_valcb(http_parser *htp, const char *data, size_t len)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_hdr_valcb(htp,data,len);
}

int htp_hdrs_completecb(http_parser *htp)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_hdrs_completecb(htp);
}

int htp_bodycb(http_parser *htp, const char *data, size_t len)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_bodycb(htp,data,len);
}

int htp_msg_completecb(http_parser *htp)
{
	auto sessionh1 = static_cast<SessionHttp1Handler *>(htp->data);
	return sessionh1->htp_msg_completecb(htp);
}
} // namespace

http_parser_settings htp_hooks = {
    htp_msg_begin,       // http_cb      on_message_begin;
    htp_uricb,           // http_data_cb on_url;
	htp_statuscb,        // http_data_cb on_status;
    htp_hdr_keycb,       // http_data_cb on_header_field;
    htp_hdr_valcb,       // http_data_cb on_header_value;
    htp_hdrs_completecb, // http_cb      on_headers_complete;
    htp_bodycb,          // http_data_cb on_body;
    htp_msg_completecb   // http_cb      on_message_complete;
};

SessionHttp1Handler::SessionHttp1Handler(enum http_parser_type type)
	: htp_(new http_parser)
{
	http_parser_init(htp_.get(), type);
	htp_->data = this;

}

SessionHttp1Handler::~SessionHttp1Handler()
{
}

int SessionHttp1Handler::recv(unsigned char *data, size_t datalen)
{
	// http_parser_execute() does nothing once it entered error state.
	auto nread = http_parser_execute(htp_.get(), &htp_hooks,
				reinterpret_cast<const char *>(data), datalen);

	http_errno httperrno = static_cast<http_errno>(htp_->http_errno);
	if(httperrno!= HPE_OK)
	{
		warnx("http_parser_execute error[%d]%s(%s)",
				httperrno,
				http_errno_name(httperrno),
				http_errno_description(httperrno));
	}

	return nread;
}


int SessionHttp1Handler::htp_uricb(http_parser *htp, const char *data, size_t len)
{
	return 0;
}

int SessionHttp1Handler::htp_statuscb(http_parser *htp, const char *data, size_t len)
{
	return 0;
}


int SessionHttp1Handler::htp_hdr_keycb(http_parser *htp, const char *data, size_t len)
{
	return 0;
}

int SessionHttp1Handler::htp_hdr_valcb(http_parser *htp, const char *data, size_t len)
{
	return 0;
}

int SessionHttp1Handler::htp_hdrs_completecb(http_parser *htp)
{
	return 0;
}

int SessionHttp1Handler::htp_bodycb(http_parser *htp, const char *data, size_t len)
{
	return 0;
}

int SessionHttp1Handler::htp_msg_completecb(http_parser *htp)
{
	return 0;
}

