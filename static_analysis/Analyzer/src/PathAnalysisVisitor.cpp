#include "PathAnalysisVisitor.h"
#include "CFGUtils.h"
#include "Constraint.h"
#include "InstructionUtils.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Support/Casting.h"

// #define DEBUG_VISIT_SWITCH_INST
// #define DEBUG_VISIT_BRANCH_INST
// #define DEBUG_CALL_INST

namespace DRCHECKER {
void PathAnalysisVisitor::visitSwitchInst(SwitchInst &I) {
#ifdef DEBUG_VISIT_SWITCH_INST
	llvm::dbgs() << "PathAnalysisVisitor::visitSwitchInst(): " << InstructionUtils::getValueStr(&I) << "\n";
#endif
	auto *cond_var = I.getCondition();
	auto *def_bb = I.getDefaultDest();
	unsigned num = I.getNumCases();

#ifdef DEBUG_VISIT_SWITCH_INST
	llvm::dbgs() << "PathAnalysisVisitor::visitSwitchInst(): Cond Var: " <<
	InstructionUtils::getValueStr(cond_var) << " Default BB: " <<
	InstructionUtils::getBBStrID(def_bb) << " #cases: " << num << "\n";
#endif

	// Collect the cases and values of this switch.
	// case bb -> the switch value(s) to it.
	std::map<llvm::BasicBlock *, std::set<int64_t>> case_map;
	std::set<int64_t> cns;
	for (auto c: I.cases()) {
		auto *val = c.getCaseValue();
		int64_t c_val = val->getSExtValue();
		cns.insert(c_val);
		auto *bb = c.getCaseSuccessor();
#ifdef DEBUG_VISIT_SWITCH_INST
		llvm::dbgs() << "Case Value: " << c_val << " Dst BB: " <<
		InstructionUtils::getBBStrID(bb) << "\n";
#endif
		if (!val || !bb) {
			continue;
		}
		case_map[bb].insert(c_val);
	}

	// Now inspect each branch of this switch, test the feasibility, and update the constraints of "cond_var" in each branch.
	// First need to see whether there are existing constaints for the "cond_var" at this point.
	auto *c = this->currState.getConstraints(this->currFuncCallSites, cond_var, true);
	assert(c);
	for (auto &e: case_map) {
		auto *bb = e.first;
		// We now need to ensure that "bb" is dominated by the switch BB, otherwise we cannot enforce the constraints
		// posed by the switch inst to it.
		if (InstructionUtils::getSinglePredecessor(bb) != I.getParent()) {
			llvm::dbgs() << "!!! PathAnalysisVisitor::visitSwitchInst(): current case BB is not dominated by the switch BB!\n";
			continue;
		}

		std::set<llvm::BasicBlock *> dombbs;
		BBTraversalHelper::getDominatees(bb, dombbs);
		expr cons = c->getEqvExpr(e.second);
		c->addConstraint2BBs(&cons, dombbs);
	}

	if (def_bb && InstructionUtils::getSinglePredecessor(def_bb) == I.getParent()) {
		std::set<llvm::BasicBlock *> dombbs;
		BBTraversalHelper::getDominatees(def_bb, dombbs);
		expr e = c->getNeqvExpr(cns);
		c->addConstraint2BBs(&e, dombbs);
	}

	this->currState.updateDeadBBs(this->currFuncCallSites, c->deadBBs);

	return;
}

VisitorCallback* PathAnalysisVisitor::visitCallInst(CallInst &I, Function *currFunc,
													std::vector<Instruction*> *oldFuncCallSites,
													std::vector<Instruction*> *callSiteContext) {
#ifdef DEBUG_CALL_INST
	llvm::dbgs() << "PathAnalysisVisitor::visitCallInst(): " <<
	InstructionUtils::getValueStr(&I) << ", callee: " <<
	currFunc->getName().str() << "\n";
#endif
	// If this is a kernel internal function, just skip it for now.
	if (currFunc->isDeclaration()) {
		return nullptr;
	}
	
	// Ok, we need to propagate the constraints from the actual args to the formal args, if any.
	int arg_no = -1;
	for (llvm::Value *arg: I.args()) {
		arg_no++;
		auto *farg = InstructionUtils::getArg(currFunc, arg_no);
		if (!arg || !farg) {
			continue;
		}
		Constraint *nc = nullptr;
		if (!llvm::dyn_cast<ConstantInt>(arg)) {
			// The actual argument is a variable, see whether it has any constraints at current point.
			Constraint *cons = this->currState.getConstraints(this->currFuncCallSites, arg, false);
			if (!cons) {
				// Try to strip the pointer cast.
				cons = this->currState.getConstraints(this->currFuncCallSites, arg->stripPointerCasts(), false);
			}
			if (!cons) {
				continue;
			}
			auto *e = cons->getConstraint(I.getParent());
			if (!e) {
				continue;
			}
#ifdef DEBUG_CALL_INST
			llvm::dbgs() << "PathAnalysisVisitor::visitCallInst(): propagate constraint for arg " << arg_no
			<< ": " << InstructionUtils::getValueStr(arg) << " -> " << InstructionUtils::getValueStr(farg) 
			<< ", constraint: " << e->to_string() << "\n";
#endif
			nc = new Constraint(farg, currFunc);
			auto *ne = new expr(z3c);
			*ne = (*e && (get_z3v_expr_bv((void *)farg) == get_z3v_expr_bv((void *)arg)));
			nc->addConstraint2AllBBs(ne);
		} else {
			// The actual argument is a constant, so obviously we need to add a constraint to the formal arg.
			nc = new Constraint(farg, currFunc);
			int64_t c_val = llvm::dyn_cast<llvm::ConstantInt>(arg)->getSExtValue();
			std::set<int64_t> vs;
			vs.insert(c_val);
			expr e = nc->getEqvExpr(vs);
#ifdef DEBUG_CALL_INST
			llvm::dbgs() << "PathAnalysisVisitor::visitCallInst(): actual arg " << arg_no << " is a constant int: "
			<< c_val << ", so add the constraint " << e.to_string() << " to the formal arg: " 
			<< InstructionUtils::getValueStr(farg) << "\n";
#endif
			nc->addConstraint2AllBBs(&e);
		}
		// Add the formal arg constraint to the global state.
		this->currState.setConstraints(callSiteContext, farg, nc);
	}

	auto *vis = new PathAnalysisVisitor(currState, currFunc, callSiteContext);

	return vis;
}

// We collect and solve simple conditionals in the form of "V op C", where V is a variable and C constant, op is simple binary operators (e.g., ==, <, >, <=, >=).
void PathAnalysisVisitor::visitBranchInst(BranchInst &I) {
	// First check whether this "br" is a simple comparison of the form we consider.
	if (!I.isConditional()) {
		return;
	}
	auto *condition = I.getCondition();
	if (!condition) {
		return;
	}
	auto *cmp_inst = llvm::dyn_cast<llvm::CmpInst>(condition);
	llvm::Value *value = nullptr;
	int64_t sc = 0;
	uint64_t uc = 0;
	llvm::CmpInst::Predicate pred, rpred;
	if (cmp_inst) {
		// OK, check whether it's the desired form (i.e., variable vs. constant).
		auto *op0 = cmp_inst->getOperand(0);
		auto *op1 = cmp_inst->getOperand(1);
		if (!op0 || !op1) {
			return;
		}

		if (llvm::dyn_cast<llvm::ConstantData>(op0) || llvm::dyn_cast<llvm::ConstantData>(op1)) {
			if (!llvm::dyn_cast<llvm::ConstantData>(op0)) {
				if (!InstructionUtils::getConstantValue(llvm::dyn_cast<llvm::Constant>(op1), &sc, &uc)) {
					return;
				}
				value = op0;
				pred = cmp_inst->getPredicate();
				rpred = cmp_inst->getInversePredicate();
			} else if (!llvm::dyn_cast<llvm::ConstantData>(op1)) {
				if (!InstructionUtils::getConstantValue(llvm::dyn_cast<llvm::Constant>(op0), &sc, &uc)) {
					return;
				}
				value = op1;
				pred = cmp_inst->getInversePredicate();
				rpred = cmp_inst->getPredicate();
			} else {
				//Both are constants? Surprising that this is not optimized out by the compiler...
				//TODO: need to find a way to skip the dead code since we can already evaluate the conditional.
				return;
			}
		} else {
			// Both are variables, ignore;
			return;
		}
	} else {
		//This means the conditional is about a boolean variable (e.g., if(b)), for which we should pose constraints.
		//NOTE: here we convert the boolean true to "1".
		value = condition;
		pred = llvm::CmpInst::Predicate::ICMP_EQ;
		rpred = llvm::CmpInst::Predicate::ICMP_NE;
		sc = uc = 1;
	}
#ifdef DEBUG_VISIT_BRANCH_INST
        llvm::dbgs() << "PathAnalysisVisitor::visitBranchInst(): Processing BR: " << InstructionUtils::getValueStr(&I) 
        << ", pred: " << pred << ", sc: " << sc << ", uc: " << uc << "\n";
#endif
	//Ok, we're ready to construct the z3 expression now.
	//Get/Create constraints for "v" in this calling context.
	auto *c = this->currState.getConstraints(this->currFuncCallSites, value, true);
	assert(c);
	auto *tb = I.getSuccessor(0);
	auto *fb = I.getSuccessor(1);
	
	if (tb && InstructionUtils::getSinglePredecessor(tb) == I.getParent()) {
		// Get all dominated BBs, these are BBs belonging only to the current branch.
		std::set<llvm::BasicBlock *> dombbs;
		BBTraversalHelper::getDominatees(tb, dombbs);
		auto cons = c->getExpr(pred, sc, uc);
		c->addConstraint2BBs(&cons, dombbs);
	}

	if (fb && InstructionUtils::getSinglePredecessor(fb) == I.getParent()) {
		// Get all dominated BBs, these are BBs belonging only to the current branch.
		std::set<llvm::BasicBlock *> dombbs;
		BBTraversalHelper::getDominatees(fb, dombbs);
		auto cons = c->getExpr(rpred, sc, uc);
		c->addConstraint2BBs(&cons, dombbs);
	}

	// Update the dead BBs to the global state, if any.
	this->currState.updateDeadBBs(this->currFuncCallSites, c->deadBBs);

	return;
}
}