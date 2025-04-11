#ifndef _ANALYZER_H_
#define _ANALYZER_H_

#include "llvm/IR/Constant.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Casting.h"
#include "spdlog/spdlog.h"

#include "common.h"

class Analyzer {
public:
	Analyzer(DeviceInfo &, std::shared_ptr<spdlog::logger>);
	virtual ~Analyzer();

	virtual void Analyze() = 0;
protected:
	DeviceInfo &device_info_;
	std::shared_ptr<spdlog::logger> logger_;

	llvm::Type* GV2Type(llvm::GlobalVariable *);
};

#endif
