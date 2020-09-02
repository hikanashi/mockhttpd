#ifndef RESPONSERULE_H_
#define RESPONSERULE_H_

#include "Common.h"
#include "HttpHeader.h"

class ServerAcceptHandler;

class ResponseRule
{
public:
	ResponseRule();
	virtual ~ResponseRule();
	
	void  setHandle(ServerAcceptHandler* handle);
	bool  IsRunning();

	virtual bool IsMatch(
				HttpRequest&     req) = 0;
	
	virtual bool IsDeleteRule() = 0;
	
	virtual int CheckRequest(
		HttpRequest&	req,
		const uint8_t*	unzip_data,
		size_t			unzip_size) = 0;

	virtual ssize_t setResponse(
							HttpRequest&  req,
							HttpResponse& res) = 0;

protected:

private:
	ServerAcceptHandler*	handle_;
};

typedef std::shared_ptr<ResponseRule> ResponseRulePtr;

#endif /* RESPONSERULE_H_ */
