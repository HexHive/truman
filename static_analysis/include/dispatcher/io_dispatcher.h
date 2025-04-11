#ifndef _IO_DISPATCHER_H_
#define _IO_DISPATCHER_H_

#include "dispatcher/dispatcher.h"

class IODispatcher: public Dispatcher {
public:
	IODispatcher(GlobalContext &);
	~IODispatcher() {};

	virtual void Dispatch(std::reference_wrapper<DeviceInfo>) override;
};

#endif
