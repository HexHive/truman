#ifndef _VISITOR_CALLBACK_H_
#define _VISITOR_CALLBACK_H_

#include <set>

#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"

namespace DRCHECKER {
/***
	*  All the flow analysis techniques which wish to use the
	*  global visitor should implement this call back.
	*/
class VisitorCallback {
public:

	/***
		*  Function which will be called by the GlobalVisitor
		*  to indicate that the analysis is within loop
		* @param inside_loop true/false which indicates
		*                    that the analysis is within loop.
		*/
	virtual void setLoopIndicator(bool inside_loop) {}
	virtual void visit(llvm::Instruction &I) {}
	virtual void visitBinaryOperator(llvm::BinaryOperator &I) {}
	virtual void visitPHINode(llvm::PHINode &I) {}
	virtual void visitSelectInst(llvm::SelectInst &I) {}
	virtual void visitLoadInst(llvm::LoadInst &I) {}
	virtual void visitStoreInst(llvm::StoreInst &I) {}
	virtual void visitGetElementPtrInst(llvm::GetElementPtrInst &I) {}
	virtual void visitAllocaInst(llvm::AllocaInst &I) {}
	virtual void visitVAArgInst(llvm::VAArgInst &I) {}
	virtual void visitVACopyInst(llvm::VACopyInst &I) {}
	virtual void visitCastInst(llvm::CastInst &I) {}
	virtual void visitICmpInst(llvm::ICmpInst &I) {}
	virtual void visitBranchInst(llvm::BranchInst &I) {}
	//hz: support switch inst.
	virtual void visitSwitchInst(llvm::SwitchInst &I) {}

	/***
		*  Visit the call instruction, this function should setup a new CallBack
		*  which will be used the GlobalVisitor to analyze the corresponding function.
		* @param I Call instruction.
		* @param targetFunction Function which is called by the provided call instruction.
		* @param oldFuncCallSites Context of the caller.
		* @param currFuncCallSites Context, basically list of call instructions.
		* @return VisitorCallback which should be used to analyze the targetFunction.
		*/
	virtual VisitorCallback* visitCallInst(llvm::CallInst &I, llvm::Function *targetFunction,
											std::vector<llvm::Instruction *> *oldFuncCallSites,
											std::vector<llvm::Instruction *> *currFuncCallSites) {
		return nullptr;
	}

	/***
		* This function provides the VisitorCallback an opportunity to stitch back the result of function callback
		*  with the original callback.
		* @param I Callinstruction handled by the childCallback
		* @param childCallback Visitor which handled the call instruction (I)
		*/
	virtual void stitchChildContext(llvm::CallInst &I, VisitorCallback *childCallback) {}
	virtual void visitReturnInst(llvm::ReturnInst &I) {}
	virtual void visit(llvm::BasicBlock *BB) {}

protected:
	// instructions where the warning has been generated.
	std::set<llvm::Instruction *> warnedInstructions;
};
}

#endif