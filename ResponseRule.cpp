#include "ResponseRule.h"
#include "ServerAcceptHandler.h"


ResponseRule::ResponseRule()
	: handle_(nullptr)
{
}

ResponseRule::~ResponseRule()
{
}


void  ResponseRule::setHandle(ServerAcceptHandler* handle)
{
	handle_ = handle;
}

bool  ResponseRule::IsRunning()
{
	if (handle_ == nullptr)
	{
		return false;
	}

	return(handle_->isRunning());

}
