#ifndef _DMA_ANALYSIS_VISITOR_H_
#define _DMA_ANALYSIS_VISITOR_H_

#include "llvm/IR/Instructions.h"

#include "VisitorCallback.h"
#include "ModuleState.h"

namespace DRCHECKER {

class DMAAnalysisVisitor : public VisitorCallback {

public:
	GlobalState &currState;
	llvm::Function *targetFunction;

	// context of the analysis, basically list of call sites
	std::vector<llvm::Instruction*> *currFuncCallSites;

	DMAAnalysisVisitor(GlobalState &targetState,
						llvm::Function *toAnalyze,
						std::vector<llvm::Instruction*> *srcCallSites): currState(targetState) {
		this->targetFunction = toAnalyze;
		this->currFuncCallSites = srcCallSites; // Initialize the call site list
		targetState.getOrCreateContext(this->currFuncCallSites); // ensure that we have a context for current function.
	}

	~DMAAnalysisVisitor() {}

	virtual void visit(llvm::Instruction &I);

	virtual VisitorCallback* visitCallInst(llvm::CallInst &I, llvm::Function *targetFunction,
											std::vector<llvm::Instruction *> *oldFuncCallSites,
											std::vector<llvm::Instruction *> *currFuncCallSites);
}; //DMAAnalysisVisitor class definition
}

#endif