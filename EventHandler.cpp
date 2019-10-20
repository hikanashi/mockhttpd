#include "EventHandler.h"
#include "event2/thread.h"

EventHandler::EventHandler() {

#ifdef _WIN32
	int err = 0;
	WSADATA wsaData;
	err = WSAStartup(MAKEWORD(2, 0), &wsaData);
	if (err != 0)
	{
		switch (err) {
		case WSASYSNOTREADY:
			warnx("WSAStartup:WSASYSNOTREADY");
			break;
		case WSAVERNOTSUPPORTED:
			warnx("WSAStartup:WSAVERNOTSUPPORTED");
			break;
		case WSAEINPROGRESS:
			warnx("WSAStartup:WSAEINPROGRESS");
			break;
		case WSAEPROCLIM:
			warnx("WSAStartup:WSAEPROCLIM");
			break;
		case WSAEFAULT:
			warnx("WSAStartup:WSAEFAULT");
			break;
		default:
			warnx("WSAStartup:%d", err);
			break;
		}
	}
#endif

#ifdef _WIN32
	evthread_use_windows_threads();
#else
	evthread_use_pthreads();
#endif

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
