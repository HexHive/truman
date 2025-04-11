#ifndef _ALIAS_DISPATCHER_H_
#define _ALIAS_DISPATCHER_H_

#include "dispatcher/dispatcher.h"

class AliasDispatcher: public Dispatcher {
public:
	AliasDispatcher(GlobalContext &);
	~AliasDispatcher() {};

	virtual void Dispatch(std::reference_wrapper<DeviceInfo>) override;
};

#endif
