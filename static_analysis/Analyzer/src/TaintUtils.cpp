#include "TaintUtils.h"
#include "InstructionUtils.h"
#include "TaintInfo.h"

#define DEBUG_ADD_NEW_TAINT_FLAG

namespace DRCHECKER {

std::set<TaintFlag *> *TaintUtils::getTaintInfo(
	GlobalState &curr_state, 
	std::vector<Instruction *> *curr_func_call_sites, 
	Value *target_val) {
	// Get total taint information for the context.
	auto *context_taint_info = curr_state.getTaintInfo(curr_func_call_sites);
	// Check if taint flags exists for the provided value?
	// if yes, fetch it.
	if (context_taint_info->find(target_val) != context_taint_info->end()) {
		return (*context_taint_info)[target_val];
	}
	// else return null
	return nullptr;
}

void TaintUtils::updateTaintInfo(
	GlobalState &curr_state, 
	std::vector<Instruction *> *curr_func_call_sites, 
	Value *target_val, 
	std::set<TaintFlag *> *target_taint_info) {
#ifdef DEBUG_ADD_NEW_TAINT_FLAG
	llvm::dbgs() << "TaintUtils::updateTaintInfo() for: " <<
	InstructionUtils::getValueStr(target_val) << "\n";
#endif
	auto *existing_taint_info =
		TaintUtils::getTaintInfo(curr_state, curr_func_call_sites, target_val);
	// If there exists no previous taint info.
	if (!existing_taint_info) {
		// get total taint information for the context.
		auto *context_taint_info = curr_state.getTaintInfo(curr_func_call_sites);
		(*context_taint_info)[target_val] = target_taint_info;
		return;
	}
	// Ok there exists previous taint info.
	// Check that for every taint flag if it is already present?
	// If yes, do not insert else insert.
	for (auto curr_taint_flag: *target_taint_info) {
		if (TaintUtils::addNewTaintFlag(existing_taint_info, curr_taint_flag)) {

		}
	}

	delete target_taint_info;
}

int TaintUtils::addNewTaintFlag(std::set<TaintFlag *> *new_taint_info, TaintFlag *new_taint_flag) {
	// Check if the set already contains same taint?
	if (std::find_if(new_taint_info->begin(), new_taint_info->end(), [new_taint_flag](const TaintFlag *n) {
		return n->isTaintEquals(new_taint_flag);
	}) == new_taint_info->end()) {
		// If not, insert the new taint flag into the new_taint_info
		new_taint_info->insert(new_taint_info->end(), new_taint_flag);
		return 1;
	} else {
		delete new_taint_flag;
	}

	return 0;
}

}