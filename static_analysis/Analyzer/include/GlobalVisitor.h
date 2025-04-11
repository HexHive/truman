#ifndef _GLOBAL_VISITOR_H_
#define _GLOBAL_VISITOR_H_

#include "llvm/IR/InstVisitor.h"

#include "ModuleState.h"
#include "VisitorCallback.h"
#include "InstructionUtils.h"

namespace DRCHECKER {

#define DEBUG_INSTR_VISIT
#define FAST_HEURISTIC
class GlobalVisitor : public InstVisitor<GlobalVisitor> {
public:
	GlobalState &currState;

	std::vector<VisitorCallback*> &allCallbacks;

	// order in which BBs needs to be analyzed.
	// This ideally should be in topological order of the
	// SCCs (Strongly connected components) in the CFG
	// of the function.
	std::vector<std::vector<BasicBlock*>*> *traversalOrder;

	// is the analysis within loop.
	bool inside_loop;

	// context of the analysis, basically list of call sites
	std::vector<Instruction*> *currFuncCallSites;

	// set of call sites already visited.
	// this will help in preventing analyzing function call
	// multiple times when in a loop.
	std::set<Instruction *> visitedCallSites;

	GlobalVisitor(GlobalState &targetState, Function *toAnalyze,
					std::vector<Instruction *> *srcCallSites,
					std::vector<std::vector<BasicBlock *> *> *bbTraversalOrder,
					std::vector<VisitorCallback *> &targetCallbacks);

	virtual void visit(Instruction &I) {
#ifdef DEBUG_INSTR_VISIT
		dbgs() << "Visiting instruction:";
		I.print(dbgs());
		dbgs() << "\n";
#endif
		for(VisitorCallback *currCallback:allCallbacks) {
			currCallback->visit(I);
		}
		this->_super->visit(I);
	}

	// visitor functions.
	virtual void visitBinaryOperator(BinaryOperator &I);
	virtual void visitPHINode(PHINode &I);
	virtual void visitSelectInst(SelectInst &I);

	virtual void visitLoadInst(LoadInst &I);
	virtual void visitStoreInst(StoreInst &I);
	virtual void visitGetElementPtrInst(GetElementPtrInst &I);

	virtual void visitAllocaInst(AllocaInst &I);

	virtual void visitVAArgInst(VAArgInst &I);
	virtual void visitVACopyInst(VACopyInst &I);

	virtual void visitCastInst(CastInst &I);

	virtual void visitCallInst(CallInst &I);
	virtual void visitReturnInst(ReturnInst &I);
	virtual void visitICmpInst(ICmpInst &I);
	virtual void visitBranchInst(BranchInst &I);

	//hz: add support for switch inst.
	virtual void visitSwitchInst(SwitchInst &I);

	virtual void visit(BasicBlock *BB);

	// main analysis function.
	void analyze();
private:
	// maximum number of times a basic block can be analyzed.
	const static unsigned long MAX_NUM_TO_VISIT = 5;
	InstVisitor *_super;

	/***
		*  Process the function which is a target of the provided call instruction.
		*
		* @param I Current call instruction.
		* @param currFunc Potential function (a target of the call instruction)
		*/
	void processCalledFunction(CallInst &I, Function *currFunc);
};
}

#endif