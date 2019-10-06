#ifndef HTTPHEADER_H_
#define HTTPHEADER_H_

#include "Common.h"
#include <string>
#include <string.h>
#include <vector>
#include "MemBuff.h"
#include "GzipInflater.h"
#include "GzipDeflater.h"

struct ci_char_traits : public std::char_traits < char >
{
	static int compare(const char *s1, const char *s2, size_t n)
	{
		return strncasecmp(s1, s2, n);
	}
};

typedef std::basic_string<char, ci_char_traits> cistring;

typedef struct HttpHeaderField
{
	cistring name;
	std::string value;
} HttpHeaderField;

typedef struct HttpHeaderBlock
{
	HttpHeaderField* get(const char* name)
	{
		for(HttpHeaderField& header : headerblock)
		{
			if(header.name ==  name )
			{
				return &header;
			}
		}
		return nullptr;
	}

	void update(
			HttpHeaderField* header)
	{
		if(header == nullptr)
		{
			return;
		}

		HttpHeaderField* hd = get(header->name.c_str());
		updateheader = true;

		if( hd != nullptr)
		{
			hd->value = header->value;
			return;
		}

		HttpHeaderField addheader;

		addheader.name = header->name;
		addheader.value = header->value;

		headerblock.push_back(addheader);
	}

	void append(
			const uint8_t *name, size_t namelen,
			const uint8_t *value,size_t valuelen)
	{
		HttpHeaderField header;
		header.name.assign((char*)name,namelen);
		header.value.assign((char*)value,valuelen);

		updateheader = true;
		headerblock.push_back(header);
	}

	void append(
			const char *name,
			const char *value)
	{
		HttpHeaderField header;
		header.name.assign(name);
		header.value.assign(value);

		updateheader = true;
		headerblock.push_back(header);
	}

	void prepend(
			HttpHeaderBlock& header)
	{
		headerblock.reserve(headerblock.size()+ header.size());
		headerblock.insert(
				headerblock.begin(),
				header.headerblock.begin(),
				header.headerblock.end());
		updateheader = true;
	}


	void remove(
			const char* name)
	{
		auto it = headerblock.begin();
		while (it != headerblock.end())
		{
			auto& header = *it;
			if(header.name == name)
			{
				it = headerblock.erase(it);
			}
			else
			{
				it++;
			}
		}

		updateheader = true;
	}

	size_t size()
	{
		return headerblock.size();
	}

	const std::vector<HttpHeaderField>& getFields()
	{
		return headerblock;
	}

private:
	std::vector<HttpHeaderField> headerblock;
	bool updateheader;
} HttpHeaderBlock;


enum HTTPPROCSTAT
{
	HTTPPROCE_STAT_INIT = 0,
	HTTPPROCE_STAT_HEADER,
	HTTPPROCE_STAT_BODY,
	HTTPPROCE_STAT_TRAILER,
	HTTPPROCE_STAT_COMPLETE
};

typedef struct HttpMessage
{
	HTTPPROCSTAT procstat;
	HttpHeaderBlock headers;
	MemBuff	payload;	// DATA body(HTTP/1.x) 
	HttpHeaderBlock trailer;
	unsigned short http_major;
	unsigned short http_minor;

	HttpMessage()
		: procstat(HTTPPROCE_STAT_INIT)
		, headers()
		, payload()
		, trailer()
		, http_major(0)
		, http_minor(0)
	{}
	virtual ~HttpMessage() {}
} HttpMessage;



typedef struct HttpRequest : public HttpMessage
{
	std::string host;
	uint16_t port;
	unsigned int methodnum;
	std::string method;
	std::string scheme;
	std::string authority;
	std::string path;
	std::unique_ptr<GzipDeflater> deflater;
	HttpRequest()
		: host()
		, port(0)
		, methodnum{0}
		, method{}
		, scheme()
		, authority()
		, path()
		, deflater()
	{}
	virtual ~HttpRequest() {}
} HttpRequest;


typedef struct HttpResponse : public HttpMessage
{
	unsigned int status_code;
	std::string reason;
	std::unique_ptr<GzipInflater> inflater;
	HttpResponse()
		: status_code(0)
		, reason()
		, inflater()
	{}
	virtual ~HttpResponse() {}
} HttpResponse;

typedef std::unique_ptr<HttpMessage> HttpMessagePtr;
typedef std::unique_ptr<HttpRequest> HttpRequestPtr;

#endif /* HTTPHEADER_H_ */
