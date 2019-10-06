#ifndef EVENTHANDLER_H_
#define EVENTHANDLER_H_

#include "Common.h"


class EventHandler {
public:
	EventHandler();
	virtual ~EventHandler();

	void loop();
	void stop();

	struct event_base* getEventBase();

private:
	struct event_base *evbase_;
};

#endif /* EVENTHANDLER_H_ */
