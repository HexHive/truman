#ifndef _PATH_ANALYSIS_VISITOR_H_
#define _PATH_ANALYSIS_VISITOR_H_

#include "llvm/IR/Instructions.h"

#include "VisitorCallback.h"
#include "ModuleState.h"

namespace DRCHECKER {
/***
	* The main class that implements the path analysis, which makes the static analysis partially path-sensitive,
	* e.g. it can detect some infeasible paths according to the path conditions, or collect path constraints.
	*/
class PathAnalysisVisitor : public VisitorCallback {

public:
	GlobalState &currState;
	llvm::Function *targetFunction;

	// context of the analysis, basically list of call sites
	std::vector<llvm::Instruction*> *currFuncCallSites;

	PathAnalysisVisitor(GlobalState &targetState,
						llvm::Function *toAnalyze,
						std::vector<llvm::Instruction*> *srcCallSites): currState(targetState) {
		this->targetFunction = toAnalyze;
		this->currFuncCallSites = srcCallSites; // Initialize the call site list
		targetState.getOrCreateContext(this->currFuncCallSites); // ensure that we have a context for current function.
	}

	~PathAnalysisVisitor() {}

	//virtual void visit(Instruction &I);
	virtual void visitSwitchInst(llvm::SwitchInst &I);
	virtual void visitBranchInst(llvm::BranchInst &I);
	virtual VisitorCallback* visitCallInst(llvm::CallInst &I, llvm::Function *targetFunction,
											std::vector<llvm::Instruction *> *oldFuncCallSites,
											std::vector<llvm::Instruction *> *currFuncCallSites);
}; //PathAnalysisVisitor class definition
}

#endif