#ifndef RESPONSERULEGENERAL_H_
#define RESPONSERULEGENERAL_H_

#include "Common.h"
#include "ResponseRule.h"

typedef enum _PATH_MATCH_PATTERN
{
	PATH_MATCH_PATTERN_COMPLETE = 0,	// Š®‘Sˆê’v
	PATH_MATCH_PATTERN_FORWARD,			// ‘O•ûˆê’v
} PATH_MATCH_PATTERN;

class ResponseRuleGeneral : public ResponseRule
{
public:
	ResponseRuleGeneral();
	ResponseRuleGeneral(
						uint32_t responce_code);
	ResponseRuleGeneral(
						uint32_t responce_code,
						const char* body, 
						size_t bodylen);
						
	virtual ~ResponseRuleGeneral();
	
	virtual bool IsMatch(
				HttpRequest&     req);
				
	virtual bool IsDeleteRule();
				
	virtual ssize_t setResponse(
		HttpRequest&  req,
		HttpResponse& res);
							
	// request match pattern
	void setHost(const char* host);
	void setPath(
				const char* path,
				PATH_MATCH_PATTERN pattern = PATH_MATCH_PATTERN_COMPLETE);
						
	void appendRequestHeaderRule(
						const char*	name,
						const char* value);
	// send response data
	void setWaitmsec( int64_t msec ) { wait_msec_ = msec; } 
	void setCloseNoResponse( bool close ){ close_no_response_ = close; }
	
	void setResponseCode(uint32_t code) { response_code_ = code; }
	void appendResponseHeaderRule(
						const char*	name,
						const char* value);
	void setBody(
						const char* body, 
						size_t bodylen);
						
	// rule life cycle
	void setCount(int32_t count) { count_ = count; }

protected:

private:
	// request match pattern
	std::string			host_;
	std::string			path_;
	PATH_MATCH_PATTERN	path_match_;
	HttpHeaderBlock		request_headers_;

	// send response data
	int64_t				wait_msec_;
	bool				close_no_response_;
	uint32_t			response_code_;
	HttpHeaderBlock		response_headers_;
	std::string			body_;

	// rule life cycle
	int32_t				count_;

};

#endif /* RESPONSERULEGENERAL_H_ */
