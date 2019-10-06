#include "EventHandler.h"

EventHandler::EventHandler() {
	evbase_ = event_base_new();
}

EventHandler::~EventHandler() {
	event_base_free(evbase_);
}

void EventHandler::loop()
{
	event_base_loop(evbase_, 0);
}

void EventHandler::stop()
{
	event_base_loopbreak(evbase_);
}

struct event_base* EventHandler::getEventBase()
{
	return evbase_;
}
