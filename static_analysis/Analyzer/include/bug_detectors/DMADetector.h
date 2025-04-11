#ifndef DMA_DETECTOR_H_
#define DMA_DETECTOR_H_

#include "llvm/IR/InstrTypes.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/CFG.h"
#include "../ModuleState.h"
#include "FunctionChecker.h"
#include "VisitorCallback.h"

namespace DRCHECKER {
class DMADetector: public VisitorCallback {
public:
	GlobalState &currState;
	Function *targetFunction;
	std::vector<Instruction *> *currFuncCallSites;
	FunctionChecker *targetChecker;

	DMADetector(GlobalState &targetState, Function *toAnalyze,
		std::vector<Instruction *> *srcCallSites,
		FunctionChecker *currChecker): currState(targetState) {
		this->targetFunction = toAnalyze;
		this->currFuncCallSites = srcCallSites;
		this->targetChecker = currChecker;
		TAG = "DMADetector says:";
	}

	virtual void visit(llvm::Instruction &I) override;

	virtual VisitorCallback* visitCallInst(CallInst &I, Function *targetFunction,
											std::vector<Instruction *> *oldFuncCallSites,
											std::vector<Instruction *> *currFuncCallSites) override;

private:
	std::string TAG;
};
}

#endif