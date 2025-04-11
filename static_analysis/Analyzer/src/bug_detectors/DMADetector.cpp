#include "TaintUtils.h"
#include "PointsToUtils.h"
#include "VisitorCallback.h"
#include "bug_detectors/DMADetector.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"

namespace DRCHECKER {
void DMADetector::visit(llvm::Instruction &I) {
	auto *val = llvm::dyn_cast<llvm::Value>(&I);
	if (!val) {
		return;
	}
	std::set<llvm::Value *> target_values;
	target_values.insert(val);

	std::set<AliasObject *> dst_objects;
	// auto *points_to_set = PointsToUtils::getPointsToObjects(
	// 	currState, this->currFuncCallSites, val);
	// if (points_to_set && !points_to_set->empty()) {
	// 	for (auto *points_to: *points_to_set) {
	// 		if (!points_to) {
	// 			continue;
	// 		}
	// 		points_to->print(llvm::dbgs());
	// 	}
	// }
	PointsToUtils::getAllAliasObjects(
		this->currState, this->currFuncCallSites, val, dst_objects);
	for (auto &dst: dst_objects) {
		target_values.insert(dst->getValue());
	}
	for (auto curr_val: target_values) {
		if (!curr_val) {
			continue;
		}
		auto *src_taint_info = TaintUtils::getTaintInfo(
			this->currState, this->currFuncCallSites, curr_val);
		if (!src_taint_info) {
			continue;
		}
		this->currState.dma_inst_set.insert(&I);
	}
}

VisitorCallback* DMADetector::visitCallInst(
	CallInst &I,
	Function *targetFunction,
	std::vector<Instruction *> *oldFuncCallSites,
	std::vector<Instruction *> *currFuncCallSites) {
	if (!targetFunction->isDeclaration()) {
		auto *new_vis = new DMADetector(
			this->currState, targetFunction, currFuncCallSites, nullptr);
		return new_vis;
	}
	return nullptr;
}
}