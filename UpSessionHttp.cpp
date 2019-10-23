#include "ServerConnection.h"
#include <string>
#include <sstream>

#include "UpSessionHttp.h"
#include "ResponseRule.h"
#include "GzipInflater.h"
#include "ServerAcceptHandler.h"

UpSessionHttp::UpSessionHttp(ServerConnection& handler)
	: UpSession(handler) , SessionHttp1Handler(HTTP_REQUEST)
	, request_()
{
}

UpSessionHttp::~UpSessionHttp()
{
}


ssize_t UpSessionHttp::on_read(unsigned char *data, size_t datalen)
{

	if (datalen == 0)
	{
		return 0;
	}

	size_t readlen = 0;


	auto nread = recv(data + readlen, datalen - readlen);
	readlen += nread;

	ssize_t ret = DoFlush();
	if (ret <= 0)
	{
		return ret;
	}

	return readlen;
}

int UpSessionHttp::htp_msg_begin(http_parser *htp)
{
	if(request_ == nullptr)
	{
		request_ = HttpRequestPtr(new HttpRequest);
		request_->procstat = HTTPPROCE_STAT_HEADER;
	}

	return 0;
}

int UpSessionHttp::htp_uricb(http_parser *htp, const char *data, size_t len)
{
	HttpRequest* req = dynamic_cast<HttpRequest*>(request_.get());

	if(req == nullptr)
	{
		return -1;
	}


	req->methodnum = htp->method;
	req->method = http_method_str((enum http_method)htp->method);

	if(req->methodnum == HTTP_CONNECT)
	{
		parseAuthority(
				data, len,
				req->host,
				req->port);
	}
	else
	{
		parseURI(data,
			len,
			req->scheme,
			req->host,
			req->port,
			req->path);
	}
	return 0;
}

int UpSessionHttp::htp_hdr_keycb(http_parser *htp, const char *data, size_t len)
{
	HttpHeaderField empty;
	curheader_ = empty;

	curheader_.name.assign(data,len);

	return 0;
}

int UpSessionHttp::htp_hdr_valcb(http_parser *htp, const char *data, size_t len)
{
	HttpRequest* req = dynamic_cast<HttpRequest*>(request_.get());
	if(req == nullptr)
	{
		return -1;
	}

	curheader_.value.assign(data,len);
	if(req->host.size() == 0 &&
		curheader_.name == "host")
	{
		req->host = curheader_.value;
	}

	if(req->procstat == HTTPPROCE_STAT_HEADER)
	{
		req->headers.append(
				(const uint8_t*)curheader_.name.c_str(), curheader_.name.size(),
				(const uint8_t*)curheader_.value.c_str(), curheader_.value.size());
	}
	else
	{
		req->trailer.append(
				(const uint8_t*)curheader_.name.c_str(), curheader_.name.size(),
				(const uint8_t*)curheader_.value.c_str(), curheader_.value.size());
	}

	return 0;
}

int UpSessionHttp::htp_hdrs_completecb(http_parser *htp)
{
	HttpRequest* req = dynamic_cast<HttpRequest*>(request_.get());
	if(req == nullptr)
	{
		return -1;
	}


	req->procstat = HTTPPROCE_STAT_BODY;
	return 0;
}

int UpSessionHttp::htp_bodycb(http_parser *htp, const char *data, size_t len)
{
	HttpRequest* req = dynamic_cast<HttpRequest*>(request_.get());
	if(req == nullptr)
	{
		return -1;
	}

	req->payload.add((const uint8_t*)data,len);
	return 0;
}

int UpSessionHttp::htp_msg_completecb(http_parser *htp)
{
	HttpRequest* req = dynamic_cast<HttpRequest*>(request_.get());
	if(req == nullptr)
	{
		return -1;
	}

	req->http_major = htp->http_major;
	req->http_minor = htp->http_minor;

	req->procstat = HTTPPROCE_STAT_COMPLETE;

	return 0;
}

ssize_t UpSessionHttp::send(
		HttpMessagePtr&	message)
{
	std::this_thread::yield();

	HttpResponse* res = dynamic_cast<HttpResponse*>(message.get());
	if(res == nullptr)
	{
		return 0;
	}

	std::stringstream sendbuf;

	sendbuf << "HTTP/" << res->http_major << "." << res->http_minor << " "
			<< res->status_code << " " << res->reason << "\r\n";

	HttpHeaderField* clfield = nullptr;
	clfield = res->headers.get("Content-Length");
	if (clfield == nullptr)
	{
		std::stringstream contentlength;
		contentlength << res->payload.size();
		res->headers.append("Content-Length", contentlength.str().c_str());
	}

	for(auto& headfield : res->headers.getFields() )
	{
		sendbuf << headfield.name.c_str() << ": " << headfield.value << "\r\n";
	}
	sendbuf << "\r\n";

	std::string buffer = sendbuf.str();
	handler_.write((uint8_t*)buffer.c_str(), buffer.size());
	warnx("%s", buffer.c_str());

	if(res->payload.size() > 0)
	{
		std::string derimiter = "\r\n";
		res->payload.add((uint8_t*)derimiter.c_str(), derimiter.size());
		size_t writelen = handler_.write(res->payload.pos(), res->payload.size());
		warnx("%s", res->payload.pos());
		res->payload.drain(writelen);
	}

	if(res->payload.size() <= 0 &&
		res->trailer.size() > 0)
	{
		sendbuf.str(""); // clear buffer
		sendbuf.clear(std::stringstream::goodbit); // clear statusbit

		for(auto& headfield : res->trailer.getFields() )
		{
			sendbuf << headfield.name.c_str() << ":" << headfield.value << "\r\n";
		}
		sendbuf << "\r\n";

		buffer = sendbuf.str();
		handler_.write((uint8_t*)buffer.c_str(), buffer.size());
		warnx("%s", buffer.c_str());
	}
	return 0;
}
size_t UpSessionHttp::sendConnectResult()
{
	std::string res = "HTTP/1.1 200 OK\r\n"
		"\r\n";

	size_t writelen = 0;
	writelen = handler_.write((const uint8_t*)res.c_str(), res.size());

	warnx("send OK Message(%d) ", writelen);
	warnx("%s", res.c_str());

	return writelen;
}


ssize_t UpSessionHttp::on_write()
{
	return 0;
}

ssize_t UpSessionHttp::on_event()
{
	return 0;
}

ssize_t UpSessionHttp::DoFlush()
{
	HttpRequest* request = dynamic_cast<HttpRequest*>(request_.get());
	if(request == nullptr)
	{
		return 0;
	}

	HttpRequest& req = *request;

	if(req.procstat != HTTPPROCE_STAT_COMPLETE)
	{
		return 0;
	}

	if (req.methodnum == HTTP_CONNECT)
	{
		sendConnectResult();
		handler_.changeTLS();
		return 0;
	}

	std::unique_ptr<HttpMessage> response(new HttpResponse());
	HttpResponse& res = *dynamic_cast<HttpResponse*>(response.get());

	ResponseRulePtr rule =
		handler_.getAccept().popResponse(req);

	if(rule.get() == nullptr)
	{
		warnx("not found response ruile");
		//		setDefaultResponse(res);
		return -1;
	}


	GzipInflater decomp(req.payload.size(), 1024);
	
	HttpHeaderField* cefield = nullptr;
	cefield = req.headers.get("Content-Encoding");
	if (cefield != nullptr &&
		cefield->value.find("gzip",0) != std::string::npos )
	{
		size_t decompsize = req.payload.size();
		decomp.inflate(req.payload.pos(), &decompsize);
	}

	ssize_t ret = 0;
	if (decomp.IsFinished() == true)
	{
		ret = rule->CheckRequest(req, decomp.data(), decomp.size());
	}
	else
	{
		ret = rule->CheckRequest(req, NULL, 0);
	}

	if (ret < 0)
	{
		return ret;
	}
		
	ret = rule->setResponse(req,res);
	if (ret < 0)
	{
		return ret;
	}

	send(response);

	HttpMessagePtr empty;
	request_.swap(empty);
	return 0;
}

void UpSessionHttp::setDefaultResponse(
	HttpResponse* res)
{
	res->http_major = 1;
	res->http_minor = 1;
	res->status_code = 404;
	res->reason = 
			http_status_str(
					(http_status)res->status_code);
}
