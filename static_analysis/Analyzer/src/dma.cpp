#include "dma.h"
#include "SVF-FE/LLVMModule.h"
#include "WPA/Andersen.h"
#include "common.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"

llvm::Type* DMAPass::GV2Type(llvm::GlobalVariable *global_variable) {
	if (!global_variable->hasInitializer())
		return NULL;

	auto *target_constant = global_variable->getInitializer();
	auto *actual_type = target_constant->getType();
	if (!actual_type->isStructTy()) {
		return NULL;
	}

	return actual_type;
}

llvm::ConstantStruct *DMAPass::FindDriver(llvm::Module *module) {
	llvm::ConstantStruct *driver_struct = NULL;
	auto &global_list = module->getGlobalList();

	for (auto &global : global_list) {
		auto *actualType = GV2Type(&global);
		if (!actualType) {
			continue;
		}
		const auto &struct_name = actualType->getStructName().str();
		if (struct_name.find("struct.pci_driver") != std::string::npos) {
			device_info_.device_type = k_PCI;
		} else if (struct_name.find("struct.platform_driver") != std::string::npos) {
			device_info_.device_type = k_PLATFORM;
		} else {
			continue;
		}
		auto *actual_constant = global.getInitializer();
		if (!actual_constant) {
			continue;
		}
		driver_struct = llvm::dyn_cast<llvm::ConstantStruct>(actual_constant);
		if (driver_struct) {
			return driver_struct;
		}
	}

	return driver_struct;
}

llvm::Function *DMAPass::FindPCIProbe(llvm::Module *M) {
	for (auto &func: M->getFunctionList()) {
		auto func_name = func.getName().str();
		if (func_name.compare("usb_hcd_pci_probe")) {
			continue;
		}
		llvm::Function *probe_func = &func;
		return probe_func;
	}

	auto *driver_struct = FindDriver(M);
	if (!driver_struct) {
		return NULL;
	}
	int func_pos = -1;
	if (device_info_.device_type == k_PCI) {
		func_pos = 3;
	} else if (device_info_.device_type == k_PLATFORM) {
		func_pos = 0;
	}
	assert(func_pos != -1);
	auto *probe_func =
		llvm::dyn_cast<llvm::Function>(driver_struct->getAggregateElement(func_pos));
	assert(probe_func);
	return probe_func;
}

bool DMAPass::AnalyzeEntries(llvm::GlobalVariable *global) {
	if (!global->hasInitializer()) {
		return false;
	}
	auto *actual_constant = global->getInitializer();
	if (!actual_constant) {
		return false;
	}
	auto ops = llvm::dyn_cast<llvm::ConstantStruct>(actual_constant);
	if (!ops) {
		return false;
	}
	auto ops_size = ops->getNumOperands();
	for (int i = 0; i < ops_size; ++i) {
		auto op = ops->getOperand(i);
		if (!op) {
			continue;
		}
		auto func = llvm::dyn_cast<llvm::Function>(op);
		if (!func || func->isDeclaration()) {
			continue;
		}
		device_info_.entries.insert(func);
	}

	return true;
}

bool DMAPass::AnalyzeEntries() {
	auto &global_list = module_->getGlobalList();

    for (auto &global : global_list) {
		auto global_name = global.getName().str();
		if (global_name.find("ops") != global_name.npos ||
				global_name.find("hc_driver") != global_name.npos ||
				global_name.find("algorithm") != global_name.npos) {
			AnalyzeEntries(&global);
		}
        auto *actualType = GV2Type(&global);
		if (!actualType) {
			continue;
		}
		const auto &struct_name = actualType->getStructName().str();
		for (auto &op: default_ops) {
			if (struct_name.find(op) == std::string::npos) {
				continue;
			}
			AnalyzeEntries(&global);
		}
    }

	return true;
}

void DMAPass::GetDebugLoc(llvm::Instruction *inst,
	std::pair<uint64_t, uint64_t> &debug_loc, bool enable_inline) {
	auto *debug_info = inst->getDebugLoc().get();
	if (!debug_info) {
		return;
	}
	if (enable_inline) {
		auto *inline_info = debug_info->getInlinedAt();
		if (inline_info) {
			debug_info = inline_info;
		}
	}
	debug_loc.first = debug_info->getLine();
	debug_loc.second = debug_info->getColumn();
}

uint64_t DMAPass::CalOffset(const llvm::GetElementPtrInst *gep_inst) {
	std::vector<llvm::Value *> idx_vec;
	for (auto &idx: gep_inst->indices()) {
		if (llvm::isa<llvm::ConstantInt>(idx)) {
			idx_vec.push_back(idx);
		} else {
			return 0xDEADC0DE;
		}
	}
	llvm::ArrayRef<llvm::Value *> array_ref{idx_vec};
	uint64_t offset = device_info_.bc_module->getDataLayout().
		getIndexedOffsetInType(gep_inst->getSourceElementType(), array_ref);

	return offset;
}

bool DMAPass::GetBytes(const SVF::VFGNode *vfg_node, uint64_t offset,
		std::set<uint64_t> &reg) {
	if (!vfg_node->getId()) {
		return false;
	}
	if (device_info_.visited_nodes.find(vfg_node) != device_info_.visited_nodes.end()) {
		return false;
	}
	device_info_.visited_nodes.insert(vfg_node);

	bool result;
	auto *value = vfg_node->getValue();
	if (!value) {
		return false;
	}
	auto *gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(value);

	if (gep_inst && vfg_node->getNodeKind() == SVF::VFGNode::VFGNodeK::Gep) {
		// io_info.device_type = Type2Str(gep_inst->getSourceElementType());
		offset += CalOffset(gep_inst);
		reg.insert(offset);
		for (auto &io_info: device_info_.io_info) {
			if (io_info.bytes.find(offset) != io_info.bytes.end()) {
				return true;
			}
		}
	}
	for (auto &in_edge: vfg_node->getInEdges()) {
		result = GetBytes(in_edge->getSrcNode(), offset, reg);
		if (result) {
			break;
		}
	}

	return result;
}

bool DMAPass::GetIOInfo(const llvm::Value *val, std::set<uint64_t> &bytes) {
	auto *pag_node = device_info_.svf_pag->getGNode(
		device_info_.svf_pag->getValueNode(val));
	auto *vfg_node = device_info_.svf_vfg->getDefVFGNode(pag_node);

	device_info_.visited_nodes.clear();
	GetBytes(vfg_node, 0, bytes);
	if (bytes.empty()) {
		bytes.insert(0);
	}

	return true;
}

std::set<llvm::Value*> DMAPass::GetStoredReturnVal(llvm::Value *val) {
	std::set<llvm::Value *> val_set;
	for (auto user: val->users()) {
		auto *cast_inst = llvm::dyn_cast<llvm::CastInst>(user);
		if (cast_inst) {
			return GetStoredReturnVal(cast_inst);
		}
		auto *store_inst = llvm::dyn_cast<llvm::StoreInst>(user);
		if (!store_inst || store_inst->getValueOperand() != val) {
			continue;
		}
		val_set.insert(store_inst->getPointerOperand());
	}

	return val_set;
}

void DMAPass::GetAliasPointers(llvm::Value *val,
		std::set<llvm::Value *> &alias_set, PointerAnalysisMap &alias_ptrs) {
	alias_set.clear();
	alias_set.insert(val);

	auto it = alias_ptrs.find(val);
	if (it == alias_ptrs.end()) {
		return;
	}

	for (auto itt: it->second) {
		alias_set.insert(itt);
	}
}

bool DMAPass::AnalyzeDMA(llvm::Function *func) {
	bool found = false;

	if (device_info_.visited_funcs.find(func) != device_info_.visited_funcs.end()) {
		return found;
	}
	device_info_.visited_funcs.insert(func);

	for (llvm::inst_iterator I = llvm::inst_begin(func),
			E = llvm::inst_end(func); I != E; ++I) {
		auto *call_inst = llvm::dyn_cast<llvm::CallInst>(&*I);
		if (!call_inst) {
			continue;
		}
		if (call_inst->isIndirectCall()) {
			continue;
		}
		auto *called_func = call_inst->getCalledFunction();
		if (!called_func || !called_func->hasName()) {
			continue;
		}
		const auto &called_func_name = called_func->getName().str();
		bool black = false;
		for (auto &item: black_list) {
			if (called_func_name.find(item) != std::string::npos) {
				black = true;
				break;
			}
		}
		if (!black && !called_func->isDeclaration()) {
			AnalyzeDMA(called_func);
		}

		for (auto &dma_func: default_dma_funcs) {
			if (called_func_name.find(std::get<0>(dma_func)) == std::string::npos) {
				continue;
			}

			DMAInfo dma = {.id = device_info_.dma_info.size(), .inst = call_inst};
			dma.type = std::get<DMA_TYPE>(dma_func);
			auto *p_func = call_inst->getParent()->getParent();
			if (dma.type == DMA_TYPE::k_COHERENT) {
				auto virt_addr_pos = std::get<1>(dma_func);
				if (virt_addr_pos != (uint8_t)-1) {
					auto *virt_addr = call_inst->getArgOperand(virt_addr_pos)->stripPointerCasts();
					GetAliasPointers(virt_addr, dma.virt_addr,
							device_info_.func_pa_results[p_func]);
					for (auto &alias: dma.virt_addr) {
						if (!llvm::isa<llvm::GetElementPtrInst>(alias)) {
							continue;
						}
						GetIOInfo(alias, dma.virt_bytes);
					}
				}
				device_info_.dma_num++;
			} else {
				auto dma_set = GetStoredReturnVal(call_inst);
				for (auto &dma_region: dma_set) {
					GetAliasPointers(dma_region, dma.phy_addr,
							device_info_.func_pa_results[p_func]);
					// for (auto &alias: dma.phy_addr) {
					// 	GetIOInfo(alias, dma.phy_bytes);
					// }
				}
			}

			device_info_.dma_info.push_back(dma);
			found = true;
		}
	}

	return found;
}

bool DMAPass::AnalyzeResource(llvm::Module *M) {
	auto *probe_func = FindPCIProbe(M);
	if (!probe_func) {
		return false;
	}
	AnalyzeEntries();

	device_info_.visited_funcs.clear();
	AnalyzeDMA(probe_func);
	for (auto &entry: device_info_.entries) {
		AnalyzeDMA(entry);
	}
	device_info_.visited_funcs.clear();

	for (auto &func: M->functions()) {
		AnalyzeDMAAccess(&func);
	}
	device_info_.visited_funcs.clear();

	return true;
}

llvm::Value *DMAPass::GetSourcePointer(llvm::Value *val) {
	llvm::Value *SrcP = val;
	llvm::Instruction *SrcI = llvm::dyn_cast<llvm::Instruction>(SrcP);

	std::list<llvm::Value *> EI;

	EI.push_back(SrcP);
	while (!EI.empty()) {
		llvm::Value *TI = EI.front();
		EI.pop_front();

		// Possible sources
		if (llvm::isa<llvm::Argument>(TI)
				|| llvm::isa<llvm::AllocaInst>(TI)
				|| llvm::isa<llvm::CallInst>(TI)
				|| llvm::isa<llvm::GlobalVariable>(TI)) {
			return SrcP;
		}

		if (llvm::UnaryInstruction *UI = llvm::dyn_cast<llvm::UnaryInstruction>(TI)) {
			llvm::Value *UO = UI->getOperand(0);
			if (UO->getType()->isPointerTy() && llvm::isa<llvm::Instruction>(UO)) {
				SrcP = UO;
				EI.push_back(SrcP);
			}
		}
		if (auto *CI = llvm::dyn_cast<llvm::CastInst>(TI)) {
			auto *UO = CI->getOperand(0);
			SrcP = UO;
			EI.push_back(SrcP);
		}
		// else if (llvm::GetElementPtrInst *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(TI)) {
		// 	SrcP = GEP->getPointerOperand();
		// 	EI.push_back(SrcP);
		// }
	}

	return SrcP;
}

bool DMAPass::AnalyzeDMAAccess(llvm::Function *func) {
	for (llvm::inst_iterator I = llvm::inst_begin(func),
			E = llvm::inst_end(func); I != E; ++I) {
		auto &inst = *I;
		if (!llvm::isa<llvm::LoadInst>(&inst) && !llvm::isa<llvm::StoreInst>(&inst)) {
			continue;
		}
		for (auto &var: inst.operands()) {
			bool flag = false;
			auto *ori_var = this->GetSourcePointer(var);
			auto *ori_inst = llvm::dyn_cast<llvm::Instruction>(ori_var);
			if (!ori_inst) {
				continue;
			}
			for (auto &dma: device_info_.dma_info) {
				if (dma.type == k_COHERENT) {
					if (dma.virt_addr.find(ori_var) != dma.virt_addr.end()) {
						flag = true;
						break;
					}
				} else {
					if (dma.phy_addr.find(ori_var) != dma.phy_addr.end()) {
						flag = true;
						break;
					}
				}
			}
			if (!flag) {
				std::set<uint64_t> bytes;
				GetIOInfo(ori_var, bytes);
				for (auto &byte: bytes) {
					for (auto &dma: device_info_.dma_info) {
						if (dma.type != k_COHERENT) {
							continue;
						}
						for (auto &virt_byte: dma.virt_bytes) {
							if (virt_byte == byte) {
								dma.virt_addr.insert(ori_var);
								flag = true;
								break;
							}
						}
						if (flag) {
							break;
						}
					}
					if (flag) {
						break;
					}
				}
			}
		}
	}

	return true;
}

void DMAPass::PreProcess() {
	device_info_.svf_module_set = SVF::LLVMModuleSet::getLLVMModuleSet();
	device_info_.svf_module = device_info_.svf_module_set->buildSVFModule(*device_info_.bc_module);
	device_info_.svf_module->buildSymbolTableInfo();
	SVF::SVFIRBuilder builder(device_info_.svf_module);
	device_info_.svf_pag = builder.build();
	device_info_.svf_ander = SVF::AndersenWaveDiff::createAndersenWaveDiff(device_info_.svf_pag);
	device_info_.svf_cg = device_info_.svf_ander->getPTACallGraph();
	device_info_.svf_icfg = device_info_.svf_pag->getICFG();
	device_info_.svf_vfg = new SVF::VFG(device_info_.svf_cg);
	SVF::SVFGBuilder svf_builder;
	device_info_.svf_svfg = svf_builder.buildFullSVFG(device_info_.svf_ander);
}

void DMAPass::CleanUp() {
	delete device_info_.svf_vfg;
	SVF::AndersenWaveDiff::releaseAndersenWaveDiff();
	SVF::SVFIR::releaseSVFIR();
	SVF::LLVMModuleSet::releaseLLVMModuleSet();
}

bool DMAPass::runOnModule(llvm::Module &M) {
	device_info_.bc_module = &M;
	device_info_.data_layout = &M.getDataLayout();
	module_ = &M;

	auto *FPasses = new llvm::legacy::FunctionPassManager(device_info_.bc_module);
	auto *AARPass = new llvm::AAResultsWrapperPass();

	FPasses->add(AARPass);
	FPasses->doInitialization();
	for (auto &func: *device_info_.bc_module) {
		if (func.isDeclaration()) {
			continue;
		}
		FPasses->run(func);
	}
	FPasses->doFinalization();

	llvm::AAResults &AAR = AARPass->getAAResults();

	for (auto &func_ref: *device_info_.bc_module) {
		auto *func = &func_ref;
		if (func->empty() || func->isDeclaration()) {
			continue;
		}

		PointerAnalysisMap alias_ptrs;

		DetectAliasPointers(func, AAR, alias_ptrs);

		device_info_.func_pa_results[func] = alias_ptrs;
		device_info_.func_aar_results[func] = &AAR;
	}

	PreProcess();
	AnalyzeResource(&M);

	auto &dma_result = getAnalysis<DMAResult>();
	dma_result.setResult(device_info_);

	// CleanUp();

	return false;
}

void DMAPass::DetectAliasPointers(llvm::Function *func,
		llvm::AAResults &AAR, PointerAnalysisMap &alias_ptrs) {
	std::set<llvm::Value *> addr_set;

	for (llvm::inst_iterator i = llvm::inst_begin(func);
			i != llvm::inst_end(func); ++i) {
		auto *I = llvm::dyn_cast<llvm::Instruction>(&*i);
		if (auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(I)) {
			addr_set.insert(load_inst->getPointerOperand());
		} else if (auto *store_inst = llvm::dyn_cast<llvm::StoreInst>(I)) {
			addr_set.insert(store_inst->getPointerOperand());
		} else if (auto *call_inst = llvm::dyn_cast<llvm::CallInst>(I)) {
			for (unsigned j = 0; j < call_inst->getNumArgOperands(); ++j) {
				auto *arg = call_inst->getArgOperand(j);
				if (!arg->getType()->isPointerTy()) {
					continue;
				}
				addr_set.insert(arg);
			}
		}
	}
	
	if (addr_set.size() > 1000) {
		return;
	}

	for (auto &addr1: addr_set) {
		for (auto &addr2: addr_set) {
			if (addr1 == addr2) {
				continue;
			}
			auto AResult = AAR.alias(addr1, addr2);
			bool no_alias = true;
			if (AResult == llvm::AliasResult::MustAlias || AResult == llvm::AliasResult::PartialAlias) {
				no_alias = false;
			} else if (AResult == llvm::AliasResult::MayAlias) {
				if (GetSourcePointer(addr1) == GetSourcePointer(addr2)) {
					no_alias = false;
				}
			}

			if (no_alias) {
				continue;
			}

			auto as = alias_ptrs.find(addr1);
			if (as == alias_ptrs.end()) {
				std::set<llvm::Value *> sv;
				sv.insert(addr2);
				alias_ptrs[addr1] = sv;
			} else {
				as->second.insert(addr2);
			}
		}
	}
}

void DMAPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
	AU.setPreservesAll();
	AU.addRequired<DMAResult>();
}

char DMAPass::ID = 0;
static llvm::RegisterPass<DMAPass> X("dma-pass", "DMA Pass", false, true);
