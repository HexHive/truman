#ifndef _ANALYSIS_H_
#define _ANALYSIS_H_

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "yaml-cpp/node/parse.h"
#include "yaml-cpp/yaml.h"
#include <tuple>

#include "dma.h"
#include "CFGUtils.h"
#include "DMAAnalysisVisitor.h"
#include "InstructionUtils.h"
#include "TaintInfo.h"
#include "TaintUtils.h"
#include "AliasObject.h"
#include "ModuleState.h"
#include "GlobalVisitor.h"
#include "RangeAnalysis.h"
#include "VisitorCallback.h"
#include "PathAnalysisVisitor.h"
#include "AliasAnalysisVisitor.h"
#include "TaintAnalysisVisitor.h"
#include "KernelFunctionChecker.h"
#include "AliasFuncHandlerCallback.h"
#include "bug_detectors/BugDetectorDriver.h"
#include "bug_detectors/DMADetector.h"

namespace DRCHECKER {

typedef struct FuncInf {
	std::string name;
	Function *func;
	std::string ty;
	std::vector<int> user_args;
} FuncInf;

struct AnalysisPass: public ModulePass {
public:
	static char ID;

	FunctionChecker *curr_func_checker_;

	AnalysisPass(): ModulePass(ID) {
		curr_func_checker_ = new KernelFunctionChecker();
	}

	~AnalysisPass() {
		delete curr_func_checker_;
	}

	void setupGlobals(Module &m);
	void addGlobalTaintSource(GlobalState &target_state);
	std::vector<std::string> split(const std::string& str, const std::string& delim);
	Function *getFuncByName(Module &m, std::string &name);
	void getTargetFunctions(llvm::Module &m);
	void setupArgs(FuncInf *fi, GlobalState &target_state, std::vector<Instruction *> *call_sites);
	void setupFunctionArgs(FuncInf *fi, GlobalState &target_state, std::vector<Instruction *> *call_sites);

	bool runOnModule(llvm::Module &m) override;
	void getAnalysisUsage(AnalysisUsage &AU) const override;
};
}

#endif
