#include "UpSession.h"
#include "http-parser/http_parser.h"
#include <sstream>

UpSession::UpSession(ServerConnection& handler)
	: handler_(handler)
{
}

UpSession::~UpSession()
{

}

int UpSession::parseAuthority(const char* authority,
				size_t		authoritylen,
				std::string& host,
				uint16_t&	port)
{
	std::string auth(authority,authoritylen);

	size_t portpos = auth.find(":", 0);
	if( portpos == std::string::npos)
	{
		host = auth;
		return 0;
	}

	host = auth.substr(0, portpos);

	port = std::atoi(auth.substr(portpos+1).c_str());

	return 0;
}

int UpSession::parseURI(const char* uri,
				size_t		urilen,
				std::string& schema,
				std::string& host,
				uint16_t&	port,
				std::string& path)
{

	struct http_parser_url u;
	int rv = http_parser_parse_url(uri, urilen, 0, &u);
	if (rv != 0)
	{
		errx(1, "Could not parse URI %s", uri);
		return -1;
	}

	if (u.field_set & (1 << UF_SCHEMA))
	{
		schema.assign(
				&uri[u.field_data[UF_SCHEMA].off],
				u.field_data[UF_SCHEMA].len);
	}

	if (u.field_set & (1 << UF_HOST))
	{
		host.assign(
				&uri[u.field_data[UF_HOST].off],
				u.field_data[UF_HOST].len);
	}

	if (u.field_set & (1 << UF_PORT))
	{
		std::string portstr;
		portstr.assign(
				&uri[u.field_data[UF_PORT].off],
				u.field_data[UF_PORT].len);
		port = std::atoi(portstr.c_str());
	}

	if (u.field_set & (1 << UF_PATH))
	{
		path.assign(
				&uri[u.field_data[UF_PATH].off],
				u.field_data[UF_PATH].len);
	}
	else
	{
		warnx("Could not PATH %s", uri);
		path = "/";
	}

	if (u.field_set & (1 << UF_QUERY))
	{
		path.append(
				&uri[u.field_data[UF_QUERY].off],
				u.field_data[UF_QUERY].len);
	}

	if (u.field_set & (1 << UF_FRAGMENT))
	{
		path.append(
				&uri[u.field_data[UF_FRAGMENT].off],
				u.field_data[UF_FRAGMENT].len);
	}



	return 0;
}


int UpSession::deflate(
		HttpMessage*	message)
{
	HttpRequest* req = dynamic_cast<HttpRequest*>(message);
	if(req == nullptr)
	{
		return -1;
	}

	size_t payloadsize = req->payload.size();
	if( payloadsize <= 0)
	{
		return 0;
	}

	if(req->deflater == nullptr)
	{
		req->deflater = std::unique_ptr<GzipDeflater>(new GzipDeflater(16384,16384));
	}

	bool finish = false;
	//if( (req->dataframe.hd.flags & NGHTTP2_FLAG_END_STREAM ) != 0)
	//{
	//	finish = true;
	//}

	int rv = req->deflater->deflate(
						req->payload.pos(),
						&payloadsize,
						finish);

	if(rv == 0)
	{
		req->payload.drain(
				payloadsize);
	}

	return rv;
}

int UpSession::deflateEnd(
		HttpMessage*	message)
{
	HttpRequest* req = dynamic_cast<HttpRequest*>(message);
	if(req == nullptr)
	{
		return -1;
	}

	if(req->deflater == nullptr)
	{
		return 0;
	}


	int rv = 0;
	// 全消去
	size_t payloadsize = req->payload.size();
	while(req->payload.size() > 0)
	{
		rv = req->deflater->deflate(
						req->payload.pos(),
						&payloadsize,
						true);
		req->payload.drain(payloadsize);
	}

	// payload replace compress data.
	req->payload.add(req->deflater->data(), req->deflater->size());

	// 
	//req->headers.append("Content-Encoding", "gzip");

	// replace contents-length
	//std::stringstream contentlength;
	//contentlength << req->payload.size();
	//HttpHeaderField* clfield = req->headers.get("Content-Length");
	//if( clfield == nullptr )
	//{
	//	req->headers.append("Content-Length", contentlength.str().c_str());
	//}
	//else
	//{
	//	clfield->value = contentlength.str();
	//}


	return rv;
}
