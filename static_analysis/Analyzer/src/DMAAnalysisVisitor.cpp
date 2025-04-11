#include "DMAAnalysisVisitor.h"
#include "AliasObject.h"
#include "CFGUtils.h"
#include "InstructionUtils.h"
#include "VisitorCallback.h"
#include "TaintInfo.h"
#include "TaintUtils.h"
#include "TaintAnalysisVisitor.h"
#include "common.h"

namespace DRCHECKER {

void DMAAnalysisVisitor::visit(llvm::Instruction &I) {
	for (auto &dma: this->currState.device_info.dma_info) {
		auto *val = llvm::dyn_cast<llvm::Value>(&I);
		bool found = false;
		if (dma.type == k_STREAMING) {
			for (auto &addr: dma.phy_addr) {
				if (addr == val) {
					found = true;
					break;
				}
			}
		} else {
			for (auto &addr: dma.virt_addr) {
				if (addr == val) {
					found = true;
					break;
				}
			}
		}
		if (found) {
			auto *loc = new InstLoc(val, this->currFuncCallSites);
			auto *curr_tag = new TaintTag(0, val, false);
			auto *curr_flag = new TaintFlag(loc, true, curr_tag);
			auto *curr_taint_info = new std::set<TaintFlag*>();
			curr_taint_info->insert(curr_flag);
			TaintUtils::updateTaintInfo(this->currState, this->currFuncCallSites, val, curr_taint_info);
		}
	}
}

VisitorCallback* DMAAnalysisVisitor::visitCallInst(
	llvm::CallInst &I,
	llvm::Function *currFunc,
	std::vector<llvm::Instruction *> *oldFuncCallSites, 
	std::vector<llvm::Instruction *> *callSiteContext) {
	
	// auto func_name = currFunc->getName().str();
	// if (!func_name.compare("dma_alloc_coherent")) {
	// 	auto *phy_dma_addr = InstructionUtils::stripAllCasts(I.getArgOperand(2), true);
	// 	auto *loc = new InstLoc(phy_dma_addr, this->currFuncCallSites);
	// 	auto *curr_tag = new TaintTag(0, phy_dma_addr, false);
	// 	auto *curr_flag = new TaintFlag(loc, true, curr_tag);
	// 	auto *curr_taint_info = new std::set<TaintFlag*>();
	// 	curr_taint_info->insert(curr_flag);
	// 	TaintUtils::updateTaintInfo(this->currState, this->currFuncCallSites, phy_dma_addr, curr_taint_info);
	// }

	// auto *obj = new FunctionArgument(
	// 	phy_dma_addr, phy_dma_addr->getType(), currFunc, this->currFuncCallSites);
	// obj->addPointerPointsTo(phy_dma_addr, loc);
	// auto *curr_points_to = this->currState.getPointsToInfo(this->currFuncCallSites);
	// if (curr_points_to) {
	// 	llvm::dbgs() << "points_to.\n";
	// 	auto *pto = new PointerPointsTo(phy_dma_addr, obj, 0, loc, false);
	// 	if (curr_points_to->find(phy_dma_addr) == curr_points_to->end()) {
	// 		(*curr_points_to)[phy_dma_addr] = new std::set<PointerPointsTo*>();
	// 	}
	// 	(*curr_points_to)[phy_dma_addr]->insert(pto);
	// }
	// obj->setAsTaintSrc(loc, false);

	// auto *ty = InstructionUtils::inferPointeeTy(&I);
	// auto *size_arg = I.getArgOperand(1);
	// for (auto inst: *this->currFuncCallSites) {
	// 	llvm::dbgs() << *inst << "\n";
	// }
	// auto *obj = new HeapLocation(I, ty, this->currFuncCallSites, size_arg, false);
	// obj->is_initialized = true;
	// obj->initializingInstructions.insert(&I);
	// auto *loc = new InstLoc(&I, this->currFuncCallSites);
	// // obj->setAsTaintSrc(loc, true);

	// PointerPointsTo *newPointsTo = new PointerPointsTo(&I, obj, 0, loc, false);
	// std::set<PointerPointsTo*> *newPointsToInfo = new std::set<PointerPointsTo*>();
	// newPointsToInfo->insert(newPointsToInfo->end(), newPointsTo);
	// for (auto *p: *newPointsToInfo) {
	// 	p->targetObject->setAsTaintSrc(loc, false);
	// }

	if (!currFunc->isDeclaration()) {
		auto *vis = new DMAAnalysisVisitor(this->currState, currFunc, callSiteContext);

		return vis;
	}
	return nullptr;
}
}