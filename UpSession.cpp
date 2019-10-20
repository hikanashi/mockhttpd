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
				&uri[u.field_data[UF_QUERY].off-1],
				u.field_data[UF_QUERY].len+1);
	}

	if (u.field_set & (1 << UF_FRAGMENT))
	{
		path.append(
				&uri[u.field_data[UF_FRAGMENT].off-1],
				u.field_data[UF_FRAGMENT].len+1);
	}



	return 0;
}
