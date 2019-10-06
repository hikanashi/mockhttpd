#include "ResponseRuleGeneral.h"
#include "http-parser/http_parser.h"
#include <algorithm>
#include "GzipDeflater.h"

ResponseRuleGeneral::ResponseRuleGeneral()
	: ResponseRule() 
	, host_()
	, path_()
	, path_match_(PATH_MATCH_PATTERN_COMPLETE)
	, request_headers_()
	, wait_msec_(0)
	, close_no_response_(false)
	, response_code_(404)
	, response_headers_()
	, response_compress_(true)
	, body_()
	, count_(1)
{
}

ResponseRuleGeneral::ResponseRuleGeneral(
						uint32_t responce_code)
	: ResponseRule() 
	, host_()
	, path_()
	, path_match_(PATH_MATCH_PATTERN_COMPLETE)
	, request_headers_()
	, wait_msec_(0)
	, close_no_response_(false)
	, response_code_(responce_code)
	, response_headers_()
	, response_compress_(true)
	, body_()
	, count_(1)
{
}

ResponseRuleGeneral::ResponseRuleGeneral(
						uint32_t responce_code,
						const char* body, 
						size_t bodylen)
	: ResponseRule() 
	, host_()
	, path_()
	, path_match_(PATH_MATCH_PATTERN_COMPLETE)
	, request_headers_()
	, wait_msec_(0)
	, close_no_response_(false)
	, response_code_(responce_code)
	, response_headers_()
	, body_(body, bodylen)
	, count_(1)
{
}

ResponseRuleGeneral::~ResponseRuleGeneral()
{
}


bool ResponseRuleGeneral::IsMatch(
				HttpRequest&     req)
{
	if(host_.size() > 0)
	{
		if (host_ != req.host)
		{
			return false;
		}
	}

	if (path_match_ == PATH_MATCH_PATTERN_COMPLETE)
	{
		if (path_.size() == 0 ||
			path_ == req.path)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	if (path_match_ == PATH_MATCH_PATTERN_FORWARD)
	{
		if (req.path.size() >= path_.size() &&
			std::equal(std::begin(path_), std::end(path_), std::begin(req.path)))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	return false;
}

bool ResponseRuleGeneral::IsDeleteRule()
{
	if (count_ <= 0)
	{
		return false;
	}
	else
	{
		count_--;
	}

	if (count_ > 0)
	{
		return false;
	}
	
	return true;
}

int ResponseRuleGeneral::CheckRequest(
	HttpRequest&	req,
	const uint8_t*	unzip_data,
	size_t			unzip_size)
{
	int ret = 0;

	if (check_function)
	{
		ret = check_function(req, unzip_data, unzip_size);
	}

	return 0;
}


ssize_t ResponseRuleGeneral::setResponse(
							HttpRequest&  req,
							HttpResponse& res)
{
	WAITMS(wait_msec_);

	if (close_no_response_)
	{
		// session close
		return -1;
	}


	res.http_major = 1;
	res.http_minor = 1;
	res.status_code = response_code_;
	res.reason =
		http_status_str(
		(http_status)res.status_code);

	for (auto& headfield : response_headers_.getFields())
	{
		res.headers.append(
				headfield.name.c_str(),
				headfield.value.c_str());
	}

	if(	body_.size() > 0 &&
		response_compress_ != false)
	{
		size_t compsize = body_.size();
		GzipDeflater comp(compsize, 1024);
		comp.deflate( (const uint8_t*)body_.c_str(), &compsize, true);

		res.payload.add(
			comp.data(),
			comp.size());

		res.headers.append(
			"Content-Encoding",
			"gzip");
	}
	else
	{
		res.payload.add(
			(const uint8_t*)body_.c_str(),
			body_.size());
	}

	return 0;
}


void ResponseRuleGeneral::setHost(
	const char* host)
{
	if (host != nullptr)
	{
		host_ = host;
	}
	else
	{
		host_.clear();
	}
}

void ResponseRuleGeneral::setPath(
						const char* path,
						PATH_MATCH_PATTERN pattern)
{
	if(path != nullptr)
	{
		path_ = path;
	}
	else
	{
		path_.clear();
	}
	
	path_match_ = pattern;
}

void ResponseRuleGeneral::appendRequestHeaderRule(
						const char*	name,
						const char* value)
{
	request_headers_.append(
						name,value);
}

void ResponseRuleGeneral::appendResponseHeaderRule(
						const char*	name,
						const char* value)
{
	response_headers_.append(
						name,value);
}

void ResponseRuleGeneral::setBody(
						const char* body, 
						size_t bodylen)
{
	if (body == nullptr || bodylen == 0)
	{
		body_.clear();
	}
	else
	{
		body_.assign(body, bodylen);
	}
}
