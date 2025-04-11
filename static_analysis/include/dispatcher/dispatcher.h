#ifndef _DISPATCHER_H_
#define _DISPATCHER_H_

#include "common.h"

class Dispatcher {
public:
	Dispatcher(GlobalContext &);
	virtual ~Dispatcher() {};

	void Process();

	virtual void Dispatch(std::reference_wrapper<DeviceInfo>) = 0;

protected:
	GlobalContext &global_context_;
	std::shared_ptr<spdlog::logger> logger_;
};

#endif
