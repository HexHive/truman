#include "llvm/IR/Instruction.h"

#include "CFGUtils.h"
#include "GlobalVisitor.h"
#include "PointsToUtils.h"
#include "InstructionUtils.h"

// #define DEBUG_GLOBAL_ANALYSIS
// #define DEBUG_CALL_INSTR
#define DONOT_CARE_COMPLETION
#define MAX_CALLSITE_DEPTH 7
#define MAX_FUNC_PTR 3
#define SMART_FUNCTION_PTR_RESOLVING
// #define DEBUG_BB_VISIT
// #define DEBUG_INST_VISIT
#define FUNC_BLACKLIST
#define HARD_LOOP_LIMIT
#define MAX_LOOP_CNT 1
#define SKIP_ASAN_INST

namespace DRCHECKER {
GlobalVisitor::GlobalVisitor(GlobalState &targetState, Function *toAnalyze,
				std::vector<Instruction *> *srcCallSites,
				std::vector<std::vector<BasicBlock *> *> *bbTraversalOrder,
				std::vector<VisitorCallback *> &targetCallbacks): allCallbacks(targetCallbacks), currState(targetState) {
	_super = static_cast<InstVisitor *>(this);
	// Initialize the call site list
	this->currFuncCallSites = srcCallSites;
	// BB traversal order should not be empty.
	assert(bbTraversalOrder != nullptr);
	this->traversalOrder = bbTraversalOrder;
	// ensure that we have a context for current function.
	targetState.getOrCreateContext(this->currFuncCallSites);
	// clearing all visited call sites.
	this->visitedCallSites.clear();
	this->inside_loop = false;
}

// Basic visitor functions.
// call the corresponding function in the child callbacks.
void GlobalVisitor::visitAllocaInst(AllocaInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitAllocaInst(I);
	}

}

void GlobalVisitor::visitCastInst(CastInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitCastInst(I);
	}
}

void GlobalVisitor::visitBinaryOperator(BinaryOperator &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitBinaryOperator(I);
	}
}

void GlobalVisitor::visitPHINode(PHINode &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitPHINode(I);
	}
}

void GlobalVisitor::visitSelectInst(SelectInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitSelectInst(I);
	}
}

void GlobalVisitor::visitGetElementPtrInst(GetElementPtrInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitGetElementPtrInst(I);
	}
}

void GlobalVisitor::visitLoadInst(LoadInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitLoadInst(I);
	}
}

void GlobalVisitor::visitStoreInst(StoreInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitStoreInst(I);
	}
}

void GlobalVisitor::visitVAArgInst(VAArgInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitVAArgInst(I);
	}
}

void GlobalVisitor::visitVACopyInst(VACopyInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitVACopyInst(I);
	}
}

void GlobalVisitor::visitReturnInst(ReturnInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitReturnInst(I);
	}
}

void GlobalVisitor::visitICmpInst(ICmpInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitICmpInst(I);
	}
}

void GlobalVisitor::visitBranchInst(BranchInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitBranchInst(I);
	}
}

//hz: add support for switch inst.
void GlobalVisitor::visitSwitchInst(SwitchInst &I) {
	for(VisitorCallback *currCallback:allCallbacks) {
		currCallback->visitSwitchInst(I);
	}
}

void GlobalVisitor::processCalledFunction(CallInst &I, Function *currFunc) {
	std::string currFuncName = currFunc->getName().str();
#ifdef DONOT_CARE_COMPLETION
	//hz: we need to use "2*MAX-1" since for each call site we insert both the call inst and the callee entry inst into the context.
	if(this->currFuncCallSites->size() > 2 * MAX_CALLSITE_DEPTH - 1) {
		// errs() << "MAX CALL SITE DEPTH REACHED, IGNORING:" << currFuncName << "\n";
		return;
	}
#endif

	//A hacking: set up a blacklist for certain time-consuming functions..
#ifdef FUNC_BLACKLIST
	std::set<std::string> black_funcs{
		"con_write","do_con_write","io_serial_out","io_serial_in","emulation_required","ccci_dump_write",
		"part_read","part_write","part_read_user_prot_reg","part_write_user_prot_reg","part_read_fact_prot_reg",
		"part_panic_write","concat_read","concat_lock","concat_unlock","part_lock","part_unlock","part_is_locked",
		"mtd_lock","mtd_unlock","part_lock_user_prot_reg","is_set_plane_size", "__const_udelay", "_printk",
	};
	std::set<std::string> black_funcs_inc{"asan_report","llvm.dbg","__sanitizer_cov_trace_pc"};
	if (black_funcs.find(currFuncName) != black_funcs.end()) {
		// dbgs() << "Func in blacklist, IGNORING:" << currFuncName << "\n";
		return;
	}
	for (auto& x : black_funcs_inc) {
		if (currFuncName.find(x) != std::string::npos) {
			return;
		}
	}
#endif
	// Create new context.
	//Set up arguments of the called function.
	std::vector<Instruction*> *newCallContext = new std::vector<Instruction *>();
	newCallContext->insert(newCallContext->end(), this->currFuncCallSites->begin(), this->currFuncCallSites->end());
	// create context.
	newCallContext->insert(newCallContext->end(), &I);
	//hz: If this is an indirect call inst, there can be multiple possible target callees, in this situation
	//if we only insert the call inst itself into the "call context", we will not be able to differentiate
	//these target callees... So now for each call inst, we insert both the call inst and the entry inst of the
	//target function into the "call context".
	if (!currFunc->isDeclaration()) {
#ifdef DEBUG_CALL_INSTR
		dbgs() << "GlobalVisitor::processCalledFunction: prepare context for: " << currFuncName << " (w/ definition)\n";
#endif
		BasicBlock &bb = currFunc->getEntryBlock();
		newCallContext->insert(newCallContext->end(), bb.getFirstNonPHIOrDbg());
	}else{
		//Insert the call inst again in order to match the 2*MAX-1...
#ifdef DEBUG_CALL_INSTR
		dbgs() << "GlobalVisitor::processCalledFunction: prepare context for: " << currFuncName << " (w/o definition)\n";
#endif
		newCallContext->insert(newCallContext->end(), &I);
	}
	this->currState.getOrCreateContext(newCallContext);

	// new callbacks that handles the current function.
	std::vector<VisitorCallback*> newCallBacks;

	// map of the parent visitor to corresponding child visitor.
	std::map<VisitorCallback*, VisitorCallback*> parentChildCallBacks;

	for (VisitorCallback *currCallback : allCallbacks) {
		VisitorCallback *newCallBack = currCallback->visitCallInst(I, currFunc, this->currFuncCallSites, newCallContext);
		if(newCallBack != nullptr) {
			newCallBacks.insert(newCallBacks.end(), newCallBack);
			parentChildCallBacks[currCallback] = newCallBack;
		}
	}
	// if there are new call backs? then create a GlobalVisitor and run the corresponding  visitor
	if (newCallBacks.size() > 0) {
		// Make sure we have the function definition.
		if (currFunc->isDeclaration()) {
			return;
		}
#ifdef DEBUG_CALL_INSTR
		dbgs() << "Analyzing new function: " << currFuncName << " Call depth: " << newCallContext->size() << "\n";
#endif
		//log the current calling context.
		dbgs() << "CTX: ";
		InstructionUtils::printCallingCtx(dbgs(),newCallContext,true);
#ifdef TIMING
		dbgs() << "[TIMING] Start func(" << newCallContext->size() << ") " << currFuncName << ": ";
		auto t0 = InstructionUtils::getCurTime(&dbgs());
#endif
		std::vector<std::vector<BasicBlock *> *> *traversalOrder = BBTraversalHelper::getSCCTraversalOrder(*currFunc);
		// Create a GlobalVisitor
		GlobalVisitor *vis = new GlobalVisitor(currState, currFunc, newCallContext, traversalOrder, newCallBacks);
		// Start analyzing the function.
		vis->analyze();

		// stitch back the contexts of all the member visitor callbacks.
		for(std::map<VisitorCallback *, VisitorCallback *>::iterator iter = parentChildCallBacks.begin();
			iter != parentChildCallBacks.end();
			++iter)
		{
			VisitorCallback *parentCallback = iter->first;
			VisitorCallback *childCallback = iter->second;
			parentCallback->stitchChildContext(I, childCallback);
			delete(childCallback);
		}
		delete(vis);
#ifdef TIMING
		dbgs() << "[TIMING] End func(" << newCallContext->size() << ") " << currFuncName << " in: ";
		InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
		//log the current calling context.
		dbgs() << "CTX: ";
		InstructionUtils::printCallingCtx(dbgs(),this->currFuncCallSites,true);
	}
}

// Visit Call Instruction.
void GlobalVisitor::visitCallInst(CallInst &I) {
	if (this->inside_loop) {
#ifdef DEBUG_CALL_INSTR
		dbgs() << "Function inside loop, will be analyzed at last iteration\n";
#endif
		return;
	}
	Function *currFunc = I.getCalledFunction();
	if (currFunc == nullptr) {
		// this is to handle casts.
		currFunc = dyn_cast<Function>(I.getCalledOperand()->stripPointerCasts());
	}
	// ignore the duplication and cycle detection only if the current function is an external function.
	if (currFunc == nullptr || !currFunc->isDeclaration()) {
		// check if the call instruction is already processed?
		if (this->visitedCallSites.find(&I) != this->visitedCallSites.end()) {
#ifdef DEBUG_CALL_INSTR
			dbgs() << "Function already processed: " << InstructionUtils::getValueStr(&I) << "\n";
#endif
			return;
		}
		//Only the odd entry in the calling context represents a call site, the even entry is the first inst of a callee.
		for (int i = 1; i < this->currFuncCallSites->size(); i += 2) {
			if ((*this->currFuncCallSites)[i] == &I) {
#ifdef DEBUG_CALL_INSTR
				dbgs() << "Call-graph cycle found: " << InstructionUtils::getValueStr(&I) << "\n";
#endif
				return;
			}
		}
	}
	// insert into visited call sites.
	this->visitedCallSites.insert(this->visitedCallSites.end(), &I);

	if(currFunc != nullptr) {
		this->processCalledFunction(I, currFunc);
	} else {
		// if this is inline assembly, ignore the call instruction.
		if(I.isInlineAsm()) {
			return;
		}
#ifdef DEBUG_CALL_INSTR
		dbgs() << "Visiting Indirect call instruction: " << InstructionUtils::getValueStr(&I) << "\n";
#endif
		Value *calledValue = I.getCalledFunction();
		if (!calledValue) {
			return;
		}
		// get points to information of calledValue and look for only functions.
		std::set<Function*> targetFunctions;
		targetFunctions.clear();
		bool hasTargets = PointsToUtils::getTargetFunctions(this->currState, this->currFuncCallSites,
															calledValue, targetFunctions);
#ifdef SMART_FUNCTION_PTR_RESOLVING
		if (!hasTargets) {
			//NOTE: the below inference is actually a backup method to the "getPossibleMemeberFunction" when
			//we fetch the field pto from an object, so if we are sure that the aforementioned inference
			//has already been performed (and we still get nothing), then no need to do the inference again here.
			Value *v = InstructionUtils::stripAllCasts(calledValue,false);
			if (v && dyn_cast<LoadInst>(v)) {
				//We must have already tried the inference when processing the "load", so give up now.
				dbgs() << "We have done the inference previously when processing the load, but still no results...\n";
				goto out;
			}
			hasTargets = InstructionUtils::getPossibleFunctionTargets(I, targetFunctions);
#ifdef DEBUG_CALL_INSTR
			dbgs() << "Function Pointer targets: " << targetFunctions.size() << "\n";
#endif
			if (targetFunctions.size() > MAX_FUNC_PTR) {
#ifdef DEBUG_CALL_INSTR
				dbgs() << "Too many Target Functions, give up some, our limit is: " << MAX_FUNC_PTR << "\n";
#endif
				std::set<Function*> tset = targetFunctions;
				targetFunctions.clear();
				int cnt = 0;
				for (Function *f : tset) {
					if (cnt >= MAX_FUNC_PTR) {
						break;
					}
					if (f) {
						targetFunctions.insert(f);
						++cnt;
					}
				}
			}
		}
#endif
out:
		// get potential target function from a given pointer.
		if(hasTargets) {
			assert(targetFunctions.size() > 0);
#ifdef DEBUG_CALL_INSTR
			dbgs() << "There are: " << targetFunctions.size() << " Target Functions.\n";
#endif
			for(Function *currFunction : targetFunctions) {
				this->processCalledFunction(I, currFunction);
			}

		} else {
#ifdef DEBUG_CALL_INSTR
			dbgs() << "Function pointer does not point to any functions: " << InstructionUtils::getValueStr(calledValue) 
			<< ", So Ignoring\n";
#endif
		}
	}
}

void GlobalVisitor::visit(BasicBlock *BB) {
	if (this->currState.numTimeAnalyzed.find(BB) != this->currState.numTimeAnalyzed.end()) {
		this->currState.numTimeAnalyzed[BB] = this->currState.numTimeAnalyzed[BB] + 1;
	} else {
		this->currState.numTimeAnalyzed[BB] = 1;
	}

#ifdef DEBUG_BB_VISIT
	llvm::dbgs() << "Starting to analyze BB: " << BB->getName().str() << ":at:"
	<< BB->getParent()->getName().str() << "\n";
#endif
	for (auto *curr_callback: allCallbacks) {
		curr_callback->visit(BB);
	}

	for (auto &inst: *BB) {
#ifdef DEBUG_INST_VISIT
	llvm::dbgs() << "\n\nStarting to analyze inst: " << inst << "\n";
#endif
		if (InstructionUtils::isAsanInst(&inst)) {
			llvm::dbgs() << "Skip ASAN inst: " << InstructionUtils::getValueStr(&inst) << "\n";
			continue;
		}
		_super->visit(inst);

		for (auto *curr_callback: allCallbacks) {
			curr_callback->visit(inst);
		}
	}

	return;
}

void GlobalVisitor::analyze() {
	assert(this->traversalOrder != nullptr);
	for (unsigned int i = 0; i < this->traversalOrder->size(); ++i) {
		// Current strongly connected component.
		auto *curr_scc = (*(this->traversalOrder))[i];
		if (curr_scc->size() == 1) {
			auto *curr_bb = (*curr_scc)[0];
			if (!this->currState.isDeadBB(this->currFuncCallSites, curr_bb)) {
				this->inside_loop = false;
				for (auto *curr_callback: allCallbacks) {
					curr_callback->setLoopIndicator(false);
				}
				this->visit(curr_bb);
			} else {
				// Current BB is infeasible
				llvm::dbgs() << "GlobalVisitor::analyze(): skip the BB since it's infeasible: "
				<< InstructionUtils::getBBStrID(curr_bb);
				llvm::dbgs() << *curr_bb << "\n";
			}
		} else {
			unsigned long opt_num_to_analyze = BBTraversalHelper::getNumTimesToAnalyze(curr_scc);
#ifdef HARD_LOOP_LIMIT
			if (opt_num_to_analyze > MAX_LOOP_CNT) {
				opt_num_to_analyze = MAX_LOOP_CNT;
			}
#endif

#ifdef DEBUG_GLOBAL_ANALYSIS
			llvm::dbgs() << "Analyzing Loop BBs for: " << opt_num_to_analyze << " number of times.\n";
#endif
			this->inside_loop = true;
			for (auto *curr_callback: allCallbacks) {
				curr_callback->setLoopIndicator(true);
			}
			for (unsigned int l = 0; l < opt_num_to_analyze; ++l) {
				// Ensure that loop has been analyzed minimum number of times.
				if (l >= (opt_num_to_analyze-1)) {
					this->inside_loop = false;
					for (auto *curr_callback: allCallbacks) {
						curr_callback->setLoopIndicator(false);
					}
				}
				for (unsigned int j = 0; j < curr_scc->size(); ++j) {
					auto *curr_BB = (*curr_scc)[j];
					if (!this->currState.isDeadBB(this->currFuncCallSites, curr_BB)) {
						this->visit(curr_BB);
					} else {
#ifdef DEBUG_GLOBAL_ANALYSIS
						llvm::dbgs() << "GlobalVisitor::analyze(): skip the BB (in a loop) since it's infeasible: " 
						<< InstructionUtils::getBBStrID(curr_BB) << "\n"; 
#endif
					}
				}
			}
#ifdef DEBUG_GLOBAL_ANALYSIS
			llvm::dbgs() << "Analyzing Loop BBS END.\n";
#endif
			// Analyzing loop.
		}
	}
	return;
}
}