#include "dma_analysis.h"

#include <mutex>
#include <filesystem>
#include <regex>
#include <string>
#include <strings.h>
#include <tuple>
#include <vector>
#include <memory>
#include <fstream>
#include <iostream>
#include <cassert>

#include <google/protobuf/util/json_util.h>
#include <google/protobuf/text_format.h>

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/IRReader/IRReader.h"
#include "MSSA/SVFGBuilder.h"
#include "SVF-FE/LLVMModule.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "WPA/Andersen.h"
#include "yaml-cpp/emitter.h"
#include "yaml-cpp/emittermanip.h"
#include "yaml-cpp/node/detail/iterator_fwd.h"
#include "yaml-cpp/yaml.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h" // Support for logging to terminal with colors

namespace DRCHECKER {

const int MAX_RING_CNT = 8;

template <typename T> std::string LLVMPrint(T* value_or_type) {
	std::string str;
	llvm::raw_string_ostream stream(str);
	value_or_type->print(stream);
	return str;
}

YAML::Emitter& operator << (YAML::Emitter& out, struct Operation op) {
	out << YAML::Flow;
	out << YAML::BeginMap;
	out << YAML::Key << "ID" << YAML::Value << op.id;
	out << YAML::Key << "Type" << YAML::Value << op.op_type;
	out << YAML::Key << "RW" << YAML::Value << op.op_rw;
	out << YAML::Key << "Name" << YAML::Value << op.name;
	out << YAML::Key << "Size" << YAML::Value << op.size;
	if (op.op_type.compare("CONFIG")) {
		out << YAML::Key << "Region ID" << YAML::Value << op.region_id;
	}
	if (op.debug_loc) {
		op.debug_loc->getInlinedAt();
		out << YAML::Key << "Line" << YAML::Value << op.debug_loc->getLine();
	}
	out << YAML::Key << "Reg" << YAML::Value << YAML::Flow << YAML::Hex << op.reg;
	if (!op.op_rw.compare("W")) {
		out << YAML::Key << "Value" << YAML::Value << *op.reg_node;
	}
	out << YAML::EndMap;
	return out;
}

YAML::Emitter& operator << (YAML::Emitter& out, struct CalleeOrOp callee_or_ops) {
	// out << YAML::BeginMap;
	// if (callee_or_ops.callee) {
	// 	out << YAML::Key << "Func" << YAML::Value <<
	// 		std::regex_replace(callee_or_ops.callee->getName().str(), std::regex("\\."), "_");
	// } else {
	// 	out << YAML::Key << "Ops" << YAML::Value << callee_or_ops.operation;
	// }
	// out << YAML::EndMap;
	if (!callee_or_ops.duplicate) {
		if (callee_or_ops.callee) {
			// TODO:
		} else {
			out << callee_or_ops.operation;
		}
	}
	return out;
}

YAML::Emitter& operator << (YAML::Emitter& out, struct IOInfo io_info) {
	out << YAML::BeginMap;
	out << YAML::Key << "MMIO" << YAML::Value << io_info.is_mmio;
	out << YAML::Key << "ID" << YAML::Value << io_info.region_id;
	out << YAML::Key << "Source Type" << YAML::Value << io_info.device_type;
	out << YAML::Key << "Offset" << YAML::Value << io_info.offset;
	out << YAML::Key << "Bytes" << YAML::Value << io_info.bytes;
	out << YAML::EndMap;
	return out;
}

YAML::Emitter& operator << (YAML::Emitter& out, struct DMAType *dma_type) {
	if (!dma_type) {
		return out;
	}
	out << YAML::BeginMap;
	if (dma_type->ele_type == k_STRUCT_) {
		out << YAML::Key << "Type" << YAML::Value << "Struct";
		out << YAML::Key << "Name" << YAML::Value << dma_type->name;
		out << YAML::Key << "Element" << YAML::Value << dma_type->dma_type;
	} else if (dma_type->ele_type == k_ARRAY_) {
		out << YAML::Key << "Type" << YAML::Value << "Array";
		out << YAML::Key << "Num" << YAML::Value << dma_type->num;
		out << YAML::Key << "Element" << YAML::Value << dma_type->dma_type;
	} else if (dma_type->ele_type == k_INT_) {
		out << YAML::Key << "Type" << YAML::Value << "Integer";
		out << YAML::Key << "Width" << YAML::Value << dma_type->width;
	} else if (dma_type->ele_type == k_POINTER_) {
		out << YAML::Key << "Type" << YAML::Value << "Pointer";
		out << YAML::Key << "Element" << YAML::Value << dma_type->dma_type;
	}
	out << YAML::EndMap;
	return out;
}

YAML::Emitter& operator << (YAML::Emitter& out, struct DMAInfo dma_info) {
	out << YAML::BeginMap;
	out << YAML::Key << "ID" << YAML::Value << dma_info.id;
	out << YAML::Key << "Inst" << YAML::Value << LLVMPrint(dma_info.inst);
	if (!dma_info.phy_bytes.empty()) {
		out << YAML::Key << "Phy" << YAML::Value << dma_info.phy_bytes;
	}
	if (!dma_info.virt_bytes.empty()) {
		out << YAML::Key << "Virt" << YAML::Value << dma_info.virt_bytes;
	}
	out << YAML::Key << "Type" << YAML::Value << dma_info.type;
	out << YAML::EndMap;
	return out;
}

YAML::Emitter& operator << (YAML::Emitter& out, std::set<std::tuple<int, int>> dma_vals) {
	out << YAML::BeginSeq;
	for (auto &dma_val: dma_vals) {
		out << std::to_string(std::get<0>(dma_val)) + " " + std::to_string(std::get<1>(dma_val)) + "\n";
	}
	out << YAML::EndSeq;
	return out;
}

bool vec_compare(const std::pair<const llvm::BasicBlock *, uint64_t> &p1,
		std::pair<const llvm::BasicBlock *, uint64_t> &p2) {
	return p1.second < p2.second;
}

bool entries_compare(llvm::Function *&func1, llvm::Function *&func2) {
	return func1->getName().str() < func2->getName().str();
}

bool func_compare(FunctionInfo &func1, FunctionInfo &func2) {
	return func1.func->getName().str() < func2.func->getName().str();
}

YAML::Emitter& operator << (YAML::Emitter& out, std::multimap<uint64_t, IntraDepNodePtr> write_regs) {
	out << YAML::Flow;
	out << YAML::BeginMap;
		for (const auto &pair: write_regs) {
			out << YAML::Key << pair.first << YAML::Value << *pair.second;
		}
	out << YAML::EndMap;
	return out;
}

YAML::Emitter& operator << (YAML::Emitter& out, struct DeviceInfo device_info) {
	out << YAML::BeginMap;
	out << YAML::Key << device_info.device_name;
	out << YAML::Value;
		out << YAML::BeginMap;
		out << YAML::Key << "Region num" << YAML::Value << device_info.io_region_num;
		out << YAML::Key << "DMA num" << YAML::Value << device_info.dma_info.size();
		out << YAML::Key << "Func num" << YAML::Value << device_info.func_infos.size();
		out << YAML::Key << "BB num" << YAML::Value << device_info.bb_ops_map.size();
		out << YAML::Key << "OP num" << YAML::Value << device_info.ops.size();
		out << YAML::Key << "Unique OP num" << YAML::Value << device_info.unique_ops;
		out << YAML::Key << "Path num" << YAML::Value << device_info.path_num;
		out << YAML::Key << "OP" << YAML::Value;
			out << YAML::BeginSeq;
			for (auto &item: device_info.ops) {
				out << YAML::Key << item;
			}
			out << YAML::EndSeq;
		out << YAML::Key << "BB" << YAML::Value;
			out << YAML::BeginSeq;
			std::vector <std::pair<const llvm::BasicBlock *, uint64_t>>
				vec(device_info.bb_num_map.begin(), device_info.bb_num_map.end());
			std::sort(vec.begin(), vec.end(), vec_compare);
			for (auto &item: vec) {
				if (device_info.bb_ops_map[item.first].empty()) {
					continue;
				}
				out << YAML::BeginMap;
				out << YAML::Key << item.first->getParent()->getName().str() + "_"
					+ std::to_string(item.second)
					<< YAML::Value;
					std::string ops;
					for (auto &op: device_info.bb_ops_map[item.first]) {
						ops += std::to_string(op) + " ";
					}
					out << ops;
				out << YAML::EndMap;
			}
			out << YAML::EndSeq;
		out << YAML::Key << "Funcs" << YAML::Value;
			out << YAML::BeginSeq;
			std::sort(device_info.func_infos.begin(),
					device_info.func_infos.end(), func_compare);
			for (auto &func: device_info.func_infos) {
				if (func.paths.empty()) {
					continue;
				}
				out << YAML::BeginMap;
				out << YAML::Key << func.func->getName().str() << YAML::Value;
					out << YAML::BeginSeq;
					int i = 0;
					for (auto &path_info: func.paths) {
						out << YAML::BeginMap;
						out << YAML::Key << i++ << YAML::Value << path_info;
						out << YAML::EndMap;
					}
					out << YAML::EndSeq;
				out << YAML::EndMap;
			}
			out << YAML::EndSeq;
		out << YAML::Key << "Probe" << YAML::Value;
			out << YAML::BeginSeq;
			for (auto &func: device_info.probe_func) {
				out << func->getName().str();
			}
			out << YAML::EndSeq;
		if (device_info.int_func) {
			out << YAML::Key << "Interrupt" << YAML::Value <<
				device_info.int_func->getName().str();
		}
		out << YAML::Key << "Entries" << YAML::Value;
			out << YAML::BeginSeq;
			std::vector<llvm::Function *> entries_vec(
					device_info.entries.begin(), device_info.entries.end());
			std::sort(entries_vec.begin(), entries_vec.end(), entries_compare);
			for (auto &item: entries_vec) {
				out << item->getName().str();
			}
			out << YAML::EndSeq;
		out << YAML::Key << "IO" << YAML::Value << device_info.io_info;
		out << YAML::Key << "DMA" << YAML::Value << device_info.dma_info;
		out << YAML::Key << "DMA Vals" << YAML::Value;
			out << YAML::BeginSeq;
			for (auto &dma: device_info.dma_insts) {
				out << LLVMPrint(dma);
			}
			out << YAML::EndSeq;
		out << YAML::Key << "DMA Nested" << YAML::Value << device_info.nested_dma;
		out << YAML::EndMap;
	out << YAML::EndMap;
	return out;
}

static cl::opt<std::string> result_bin("result", cl::desc("result file"), cl::value_desc("result file"), cl::init("result.bin"));
static cl::opt<std::string> target("target", cl::desc("target device"), cl::value_desc("target device"), cl::init("target"));

void DMAAnalysisPass::printAliasPoints() {
    for (const auto &func_map : device_info_.func_pa_results) {
        llvm::Function *F = func_map.first;
        const PointerAnalysisMap &pa_map = func_map.second;

        llvm::outs() << "Function: " << F->getName() << "\n";
        for (const auto &pair : pa_map) {
            llvm::Value *key = pair.first;
            const std::set<llvm::Value *> &alias_set = pair.second;

            llvm::outs() << "  Value: " << *key << "\n";
            llvm::outs() << "    Aliases:\n";
            for (llvm::Value *alias : alias_set) {
                llvm::outs() << "      " << *alias << "\n";
            }
        }
    }
}

bool DMAAnalysisPass::runOnModule(llvm::Module &M) {
	device_info_ = getAnalysis<DMATaintResult>().getResult();
	device_info_.bc_module = &M;
	device_info_.device_name = target;
	module_ = &M;

	try {
        auto console_logger = spdlog::stdout_color_mt("console");
        spdlog::set_default_logger(console_logger);
		console_logger->set_pattern("%^[%T] %v%$");
#if defined(NDEBUG)
		// spdlog::set_level(spdlog::level::info); // Release or RelWithDebInfo
		spdlog::set_level(spdlog::level::off);
#else
		spdlog::set_level(spdlog::level::trace); // Debug
#endif
    } catch (const spdlog::spdlog_ex &ex) {
        llvm::errs() << "Log initialization failed: " << ex.what() << "\n";
    }

	// PreProcess();
	Analyze();
	WriteResult();
	// CleanUp();
	
	// printAliasPoints();

	return false;
}

void DMAAnalysisPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
	AU.setPreservesAll();
	AU.addRequired<DMATaintResult>();
	AU.addRequired<DMAResult>();
	AU.addRequired<DMAPass>();
	AU.addRequired<AnalysisPass>();
}

void DMAAnalysisPass::Analyze() {
	SPDLOG_INFO("Start to analyze the target {}", device_info_.bc_module->getName().str());

	if (!AnalyzeProbe()) {
		SPDLOG_ERROR("Cannot analyze the probe function!");
		return;
	}

	if (device_info_.int_func) {
		AnalyzeFunc(device_info_.int_func);
	}

	for (auto &func: device_info_.funcs) {
		AnalyzePath(func);
	}

	// for (auto &func: device_info_.funcs) {
	// 	AnalyzeDMAAccess(func);
	// }

	AnalyzeNestedDMA();
	
	return;
}

#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"

bool DMAAnalysisPass::hasOneVariableIndex(llvm::GetElementPtrInst *GEP) {
	int variableIndexCount = 0;

	for (auto idx = GEP->idx_begin(), end = GEP->idx_end(); idx != end; ++idx) {
		llvm::Value *index = idx->get();
		if (!llvm::isa<llvm::Constant>(index)) {
			variableIndexCount++;
		}
	}

	return variableIndexCount == 1;
}

void DMAAnalysisPass::AnalyzeNestedDMA() {
	// assert(device_info_.dma_num == 1);
	for (auto &dma: device_info_.dma_insts) {
		auto *gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(dma);
		if (!gep_inst || !hasOneVariableIndex(gep_inst)) {
			continue;
		}
		auto *source_type = gep_inst->getSourceElementType();
		if (!source_type->isStructTy()) {
			continue;
		}
		uint64_t source_type_size = device_info_.data_layout->getTypeAllocSize(source_type);
		int var_pos = -1;
		int cnt = 0;
		llvm::SmallVector<llvm::Value *, 8> origin_indices;
		for (auto idx = gep_inst->idx_begin(); idx != gep_inst->idx_end(); ++idx) {
			cnt++;
			auto *index = idx->get();
			auto *constant = llvm::dyn_cast<llvm::ConstantInt>(index);;
			if (!constant) {
				assert(var_pos == -1);
				var_pos = cnt;
				origin_indices.emplace_back(C2C(0xdeadbeef));
			} else {
				origin_indices.emplace_back(constant);
			}
		}
		cnt = 0;
		while (true) {
			llvm::SmallVector<llvm::Value *, 8> indices;
			for (auto ori: origin_indices) {
				auto *constant_value = llvm::dyn_cast<llvm::ConstantInt>(ori);
				if (!constant_value) {
					continue;
				}
				auto constant = constant_value->getZExtValue();
				if (constant != 0xdeadbeef) {
					indices.emplace_back(ori);
				} else {
					indices.emplace_back(C2C(cnt));
				}
			}
			int total_size = device_info_.data_layout->
				getIndexedOffsetInType(source_type, indices);
			if (cnt > MAX_RING_CNT || total_size > source_type_size) {
				break;
			}
			cnt++;
			device_info_.nested_dma.insert(total_size);
		}
	}
}

llvm::Value *DMAAnalysisPass::C2C(uint64_t value) {
	auto &context = device_info_.bc_module->getContext();
	llvm::Type *int32Type = llvm::Type::getInt32Ty(context);

	// Create the constant value as an APInt
	llvm::APInt apIntValue(32, value);

	// Create the llvm::ConstantInt object
	llvm::Constant *constant = llvm::ConstantInt::get(context, apIntValue);
	return constant;
}

llvm::Value *DMAAnalysisPass::GetSourcePointer(llvm::Value *val) {
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

// bool DMAAnalysisPass::AnalyzeDMAAccess(llvm::Function *func) {
// 	std::pair<uint64_t, uint64_t> debug_loc;
// 	for (llvm::inst_iterator I = llvm::inst_begin(func),
// 			E = llvm::inst_end(func); I != E; ++I) {
// 		auto &inst = *I;
// 		if (!llvm::isa<llvm::LoadInst>(&inst) && !llvm::isa<llvm::StoreInst>(&inst)) {
// 			continue;
// 		}
// 		for (auto &var: inst.operands()) {
// 			bool flag = false;
// 			auto *ori_var = this->GetSourcePointer(var);
// 						auto *ori_inst = llvm::dyn_cast<llvm::Instruction>(ori_var);
// 			if (!ori_inst) {
// 				continue;
// 			}
// 			for (auto &dma: device_info_.dma_info) {
// 				if (dma.type == k_COHERENT) {
// 					if (dma.virt_addr.find(ori_var) != dma.virt_addr.end()) {
// 						flag = true;
// 						break;
// 					}
// 				} else {
// 					if (dma.phy_addr.find(ori_var) != dma.phy_addr.end()) {
// 						flag = true;
// 						break;
// 					}
// 				}
// 			}
// 			if (!flag) {
// 				std::set<uint64_t> bytes;
// 				GetIOInfo(ori_var, bytes);
// 				for (auto &byte: bytes) {
// 					for (auto &dma: device_info_.dma_info) {
// 						if (dma.type == k_COHERENT) {
// 							for (auto &virt_byte: dma.virt_bytes) {
// 								if (virt_byte == byte) {
// 									flag = true;
// 									break;
// 								}
// 							}
// 						}
// 						if (flag) {
// 							break;
// 						}
// 					}
// 					if (flag) {
// 						break;
// 					}
// 				}
// 			}
// 			if (flag) {
// 				GetDebugLoc(ori_inst, debug_loc, false);
// 				device_info_.dma_vals.insert(std::make_tuple(debug_loc.first, debug_loc.second));
// 			}
// 		}
// 	}
// 
// 	return true;
// }

bool DMAAnalysisPass::AnalyzeProbe() {
	auto *probe_func = FindPCIProbe();
	if (!probe_func) {
		SPDLOG_ERROR("Cannot find the probe function!");
		return false;
	}
	device_info_.probe_func.insert(probe_func);

	device_info_.visited_funcs.clear();
	if (!AnalyzeIOBar(probe_func)) {
		SPDLOG_ERROR("Cannot find the IO bar!");
		return false;
	}

	AnalyzeEntries();

	// device_info_.visited_funcs.clear();
	// AnalyzeDMA(probe_func);
	// for (auto &entry: device_info_.entries) {
	// 	AnalyzeDMA(entry);
	// }

	device_info_.visited_funcs.clear();
	for (auto &func: device_info_.probe_func) {
		AnalyzeFunc(func);
	}
	
	return true;
}

// bool DMAAnalysisPass::AnalyzeDMA(llvm::Function *func) {
// 	bool found = false;
// 
// 	if (device_info_.visited_funcs.find(func) != device_info_.visited_funcs.end()) {
// 		return found;
// 	}
// 	device_info_.visited_funcs.insert(func);
// 
// 	for (llvm::inst_iterator I = llvm::inst_begin(func),
// 			E = llvm::inst_end(func); I != E; ++I) {
// 		auto *call_inst = llvm::dyn_cast<llvm::CallInst>(&*I);
// 		if (!call_inst) {
// 			continue;
// 		}
// 		auto *called_func = call_inst->getCalledFunction();
// 		if (!called_func || !called_func->hasName()) {
// 			continue;
// 		}
// 		const auto &called_func_name = called_func->getName().str();
// 		bool black = false;
// 		for (auto &item: black_list) {
// 			if (called_func_name.find(item) != std::string::npos) {
// 				black = true;
// 				break;
// 			}
// 		}
// 		if (!black && !called_func->isDeclaration()) {
// 			AnalyzeDMA(called_func);
// 		}
// 
// 		for (auto &dma_func: default_dma_funcs) {
// 			if (called_func_name.find(std::get<0>(dma_func)) == std::string::npos) {
// 				continue;
// 			}
// 			auto dma_type = std::get<DMA_TYPE>(dma_func);
// 
// 				std::pair<uint64_t, uint64_t> debug_loc;
// 				GetDebugLoc(call_inst, debug_loc, false);
// 				for (auto &dma: device_info_.dma_info) {
// 					if (debug_loc != dma.debug_loc) {
// 						continue;
// 					}
// 					auto dma_set = GetStoredReturnVal(call_inst);
// 					auto *p_func = call_inst->getParent()->getParent();
// 					for (auto &dma_region: dma_set) {
// 						GetAliasPointers(dma_region, dma.phy_addr,
// 								device_info_.func_pa_results[p_func]);
// 						for (auto &alias: dma.phy_addr) {
// 														GetIOInfo(alias, dma.phy_bytes);
// 						}
// 					}
// 
// 					auto virt_addr_pos = std::get<1>(dma_func);
// 					if (virt_addr_pos != (uint8_t)-1) {
// 						auto *virt_addr = call_inst->getArgOperand(virt_addr_pos)->stripPointerCasts();
// 						GetAliasPointers(virt_addr, dma.virt_addr,
// 								device_info_.func_pa_results[p_func]);
// 						for (auto &alias: dma.virt_addr) {
// 							if (!llvm::isa<llvm::GetElementPtrInst>(alias)) {
// 								continue;
// 							}
// 							GetIOInfo(alias, dma.virt_bytes);
// 						}
// 					}
// 			}
// 			found = true;
// 			break;
// 		}
// 	}
// 
// 	return found;
// }

// struct DMAType *DMAAnalysisPass::GetDMAType(llvm::Type *type) {
// 	auto dma_type = new struct DMAType;
// 	if (type->isStructTy()) {
// 		dma_type->ele_type = k_STRUCT_;
// 		dma_type->name = type->getStructName().str();
// 		auto ele_num = type->getStructNumElements();
// 		for (int i = 0; i < ele_num; ++i) {
// 			dma_type->dma_type.emplace_back(GetDMAType(type->getStructElementType(i)));
// 		}
// 	} else if (type->isArrayTy()) {
// 		dma_type->ele_type = k_ARRAY_;
// 		dma_type->num = type->getArrayNumElements();
// 		dma_type->dma_type.emplace_back(GetDMAType(type->getArrayElementType()));
// 	} else if (type->isIntegerTy()) {
// 		dma_type->ele_type = k_INT_;
// 		dma_type->width = type->getIntegerBitWidth();
// 	} else if (type->isPointerTy()) {
// 		dma_type->ele_type = k_POINTER_;
// 		dma_type->dma_type.emplace_back(GetDMAType(type->getPointerElementType()));
// 	} else {
// 			}
// 
// 	return dma_type;
// }

void DMAAnalysisPass::GetDebugLoc(llvm::Instruction *inst,
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

bool DMAAnalysisPass::AnalyzeIOBar(llvm::Function *func) {
	bool found = false;

	if (device_info_.visited_funcs.find(func) != device_info_.visited_funcs.end()) {
		return found;
	}
	device_info_.visited_funcs.insert(func);

	// Check the return value of the mapping functions
	for (llvm::inst_iterator I = llvm::inst_begin(func),
			E = llvm::inst_end(func); I != E; ++I) {
		if (auto *call_inst = llvm::dyn_cast<llvm::CallInst>(&*I)) {
			if (call_inst->isIndirectCall()) {
				SPDLOG_WARN("Cannot handle indirect call {}", LLVMPrint(call_inst));
			}
			auto *called_func = call_inst->getCalledFunction();

			if (!called_func) {
				if (auto *const_expr = llvm::dyn_cast<llvm::ConstantExpr>(call_inst->getCalledOperand())) {
                    if (const_expr->isCast()) {
                        called_func = llvm::dyn_cast<llvm::Function>(const_expr->getOperand(0));
                    }
                }
            }

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
				bool found = AnalyzeIOBar(called_func);
				if (found) {
					return found;
				}
			}

			for (auto &func: mmio_mapping_funcs) { // iomap related functions
				if (called_func_name.compare(func)) {
					continue;
				}
				struct IOInfo io_info = {device_info_.io_region_num++, true};
				io_info.var.insert(call_inst);
				std::set<llvm::Value *> io_region_set;
				if (!called_func_name.compare("pcim_iomap_table")) {
					for (auto user: call_inst->users()) {
						auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(user);
						if (!load_inst) {
							continue;
						}
						io_region_set = GetStoredReturnVal(load_inst);
					}
				} else {
					io_region_set = GetStoredReturnVal(call_inst);
				}
				for (auto &io_region: io_region_set) {
					io_info.var.insert(io_region);
					std::set<llvm::Value *> alias_set;
					auto *p_func = call_inst->getParent()->getParent();
					GetAliasPointers(io_region, alias_set,
							device_info_.func_pa_results[p_func]);
					GetIOInfo(io_region, io_info.bytes);
				}
				device_info_.io_info.emplace_back(io_info);

				found = true;
				break;
			}
		} else if (auto *gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(&*I)) {
			auto *source_type = gep_inst->getSourceElementType();
			if (!source_type->isStructTy()) {
				continue;
			}
			auto source_type_name = source_type->getStructName().str();
			if (source_type_name.compare("struct.pci_dev")) {
				continue;
			}

			std::vector<uint64_t> offset;
			ExtractInt(gep_inst, offset);

			// heuristic rule
			if (offset.size() != 4 || offset[0] != 0 || offset[1] != 51 || offset[3] != 0) {
				continue;
			}

			std::set<uint64_t> reg;
			struct IOInfo p_io_info{device_info_.io_region_num++, false, source_type_name, offset, reg};
			device_info_.io_info.push_back(p_io_info);
			
			found = true;
		} else if (auto *store_inst = llvm::dyn_cast<llvm::StoreInst>(&*I)) {
			auto *operand_type = store_inst->getValueOperand()->getType();
			if (operand_type->isPointerTy()) {
				operand_type = operand_type->getPointerElementType();
				if (operand_type->isFunctionTy()) {
					auto *probe_work = llvm::dyn_cast<llvm::Function>(store_inst->getValueOperand());
					if (probe_work && !probe_work->isDeclaration() &&
							probe_work->getName().str().find("probe") != std::string::npos) {
						device_info_.probe_func.insert(probe_work);
						bool found = AnalyzeIOBar(probe_work);
						if (found) {
							return found;
						}
					}
				}
			}
		}
	}

	return found;
}

bool DMAAnalysisPass::GetBytes(const SVF::VFGNode *vfg_node, uint64_t offset,
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

bool DMAAnalysisPass::GetIOInfo(const llvm::Value *val, std::set<uint64_t> &bytes) {
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

std::set<llvm::Value*> DMAAnalysisPass::GetStoredReturnVal(llvm::Value *val) {
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

bool DMAAnalysisPass::AnalyzeEntries(llvm::GlobalVariable *global) {
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
		AnalyzeFunc(func);
	}

	return true;
}

llvm::Type* DMAAnalysisPass::GV2Type(llvm::GlobalVariable *global_variable) {
    if (!global_variable->hasInitializer())
        return NULL;

    auto *target_constant = global_variable->getInitializer();
	auto *actual_type = target_constant->getType();
	if (!actual_type->isStructTy()) {
		return NULL;
	}

	return actual_type;
}

bool DMAAnalysisPass::AnalyzeEntries() {
	llvm::Module *bc;
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

	for (auto &func: module_->functions()) {
		if (func.isDeclaration()) {
			continue;
		}
		device_info_.entries.insert(&func);
		AnalyzeFunc(&func);
	}

	return true;
}

struct CalleeOrOp DMAAnalysisPass::AnalyzeCall(llvm::CallInst *call_inst) {
	struct CalleeOrOp callee_or_op;

	if (call_inst->isIndirectCall()) {
		SPDLOG_WARN("Cannot handle indirect call {}.\n", LLVMPrint(call_inst));
		auto *op_inst = llvm::dyn_cast<llvm::LoadInst>(call_inst->getCalledOperand());
		if (op_inst) {
			auto *source = op_inst->getPointerOperand();
			auto source_name = source->getName();
			if (source_name.contains("read")) {
				// Handle read case if necessary
			} else if (source_name.contains("write")) {
				// Handle write case if necessary
			}
		}
	}

	auto *asm_ptr = llvm::dyn_cast<llvm::InlineAsm>(call_inst->getCalledOperand());
	if (asm_ptr) {
		const auto &asm_string = asm_ptr->getAsmString();
		for (auto &rw_func : default_asm_funcs) {
			if (asm_string.compare(std::get<0>(rw_func))) {
				continue;
			}

			callee_or_op.operation.call_inst = call_inst;
			callee_or_op.operation.debug_loc = call_inst->getDebugLoc();
			if (auto *inline_info = callee_or_op.operation.debug_loc->getInlinedAt()) {
				callee_or_op.operation.debug_loc = inline_info;
			}

			callee_or_op.operation.size = std::get<2>(rw_func);
			auto op_type = std::get<OP_TYPE>(rw_func);
			switch (op_type) {
				case k_MMIO:
					callee_or_op.operation.op_type = "MMIO";
					break;
				case k_IO:
					callee_or_op.operation.op_type = "IO";
					break;
				case k_CONFIG:
					callee_or_op.operation.op_type = "CONFIG";
					break;
				default:
					break;
			}

			if (std::get<RW>(rw_func) == k_WRITE) {
				callee_or_op.operation.op_rw = "W";
				if (op_type == k_MMIO) {
					callee_or_op.operation.name = "write" + asm_string.substr(3, 1);
				} else {
					callee_or_op.operation.name = asm_string.substr(0, 4);
				}
				device_info_.visited_reg_values.clear();
				device_info_.val2node_map.clear();
				auto reg_node = GetRegValue(call_inst->getArgOperand(0));
				if (reg_node->ChildrenSize() || (!reg_node->ChildrenSize() && reg_node->node_value_type != k_NODE_VALUE_NUM_TYPE && reg_node->node_value_type != k_NODE_VALUE_CALL)) {
					device_info_.intra_num++;
				}
				callee_or_op.operation.reg_node = reg_node;
				callee_or_op.operation.reg = GetReg(call_inst->getArgOperand(1), callee_or_op.operation.region_id, op_type == k_IO);
			} else {
				callee_or_op.operation.op_rw = "R";
				if (op_type == k_MMIO) {
					callee_or_op.operation.name = "read" + asm_string.substr(3, 1);
				} else {
					callee_or_op.operation.name = asm_string.substr(0, 3);
				}
				callee_or_op.operation.reg = GetReg(call_inst->getArgOperand(0), callee_or_op.operation.region_id, op_type == k_IO);
			}

			callee_or_op.kind = CalleeOrOp::IsOperation;
			return callee_or_op;
		}
	}

	auto *called_func = call_inst->getCalledFunction();
	if (!called_func || !called_func->hasName()) {
		return callee_or_op;
	}

	const auto &called_func_name = called_func->getName().str();
	if (called_func_name == "request_threaded_irq") {
		auto *int_func = llvm::dyn_cast<llvm::Function>(call_inst->getArgOperand(1));
		if (int_func && !int_func->isDeclaration()) {
			device_info_.int_func = int_func;
		}
	}

	for (auto &rw_func : default_rw_funcs) {
		if (called_func_name.find(std::get<0>(rw_func)) == std::string::npos) {
			continue;
		}

		SPDLOG_DEBUG("Analyzing call {} in function {}", LLVMPrint(call_inst), call_inst->getParent()->getParent()->getName().str());
		callee_or_op.operation.call_inst = call_inst;
		callee_or_op.operation.debug_loc = call_inst->getDebugLoc().get();

		auto op_type = std::get<OP_TYPE>(rw_func);
		switch (op_type) {
			case k_MMIO:
				callee_or_op.operation.op_type = "MMIO";
				break;
			case k_IO:
				callee_or_op.operation.op_type = "IO";
				break;
			case k_CONFIG:
				callee_or_op.operation.op_type = "CONFIG";
				break;
			default:
				break;
		}

		callee_or_op.operation.name = called_func_name;
		callee_or_op.operation.size = std::get<2>(rw_func);
		auto reg_pos = std::get<5>(rw_func);
		auto offset_pos = std::get<6>(rw_func);
		auto val_pos = std::get<7>(rw_func);

		if (reg_pos != (uint8_t)-1) {
			callee_or_op.operation.reg.insert(GetValue(call_inst->getArgOperand(offset_pos)));
			GetReg(call_inst->getArgOperand(reg_pos), callee_or_op.operation.region_id, op_type == k_IO);
		} else {
			callee_or_op.operation.reg = GetReg(call_inst->getArgOperand(offset_pos), callee_or_op.operation.region_id, op_type == k_IO);
		}

		if (std::get<RW>(rw_func) == k_WRITE) {
			callee_or_op.operation.op_rw = "W";
			device_info_.visited_reg_values.clear();
			device_info_.val2node_map.clear();
			auto reg_node = GetRegValue(call_inst->getArgOperand(val_pos));
			if (reg_node->ChildrenSize() || (!reg_node->ChildrenSize() && reg_node->node_value_type != k_NODE_VALUE_NUM_TYPE && reg_node->node_value_type != k_NODE_VALUE_CALL)) {
				device_info_.intra_num++;
			}
			callee_or_op.operation.reg_node = reg_node;
		} else {
			callee_or_op.operation.op_rw = "R";
		}

		callee_or_op.kind = CalleeOrOp::IsOperation;
		return callee_or_op;
	}

	if (std::any_of(black_list.begin(), black_list.end(), [&](const std::string& item) { return called_func_name.find(item) != std::string::npos; })) {
		return callee_or_op;
	}

	if (!called_func->isDeclaration()) {
		AnalyzeFunc(called_func);
		callee_or_op.callee = called_func;
		callee_or_op.kind = CalleeOrOp::IsCallee;
		return callee_or_op;
	}

	return callee_or_op;
}

uint64_t DMAAnalysisPass::FindOpOrCallee(const CalleeOrOp& op) {
    uint64_t id = -1;
    if (op.callee) {
        // Check for callee
        for (const auto& item : device_info_.ops) {
            if (item.callee && item.callee == op.callee) {
                id = item.id;
                break;
            }
        }
    } else {
        // Check for operation
        for (const auto& item : device_info_.ops) {
            if (!item.callee && 
                item.operation.region_id == op.operation.region_id &&
                item.operation.name == op.operation.name &&
                item.operation.size == op.operation.size &&
                IntraDepNode::areTreesEqual(item.operation.reg_node, op.operation.reg_node) &&
                item.operation.reg == op.operation.reg) {
                id = item.operation.id;
                break;
            }
        }
    }
    return id;
}

bool DMAAnalysisPass::AnalyzeBB(llvm::BasicBlock *bb) {
	// Check if the basic block has already been visited
	if (device_info_.visited_bbs.find(bb) != device_info_.visited_bbs.end()) {
		return true;
	}
	// Mark the basic block as visited
	device_info_.visited_bbs.insert(bb);
	Ops ops;

	// Assign a unique number to the basic block
	device_info_.bb_num_map[bb] = ++device_info_.bb_num;

	// Iterate over each instruction in the basic block
	for (auto &inst : *bb) {
		// Cast the instruction to a CallInst, if possible
		auto *call_inst = llvm::dyn_cast<llvm::CallInst>(&inst);
		if (!call_inst) {
			continue;
		}
		// Analyze the call instruction to get a CalleeOrOp object
		auto callee_or_op = AnalyzeCall(call_inst);

		// Determine if the CalleeOrOp is valid
		bool is_valid = callee_or_op.callee || callee_or_op.operation.call_inst;
		if (!is_valid) {
			continue;
		}

		uint64_t id = FindOpOrCallee(callee_or_op);
		if (id == -1) {
			if (callee_or_op.kind == CalleeOrOp::IsOperation) {
				device_info_.unique_ops++;
			}
			callee_or_op.id = device_info_.ops.size() + 1;
		} else {
			callee_or_op.duplicate = true;
			callee_or_op.id = id;
		}

		// Insert the callee_or_op into the device_info_.ops and the local ops vector
		device_info_.ops.push_back(callee_or_op);
		ops.push_back(callee_or_op.id);
	}

	// If there are operations recorded for this basic block, update the map
	if (!ops.empty()) {
		device_info_.bb_ops_map[bb] = ops;
	}
	return true;
}

std::set<PathInfo> DMAAnalysisPass::AnalyzePath(llvm::BasicBlock *bb,
		std::set<llvm::BasicBlock *> &bb_set) {
	std::set<PathInfo> path_info_set;

	if (bb_set.find(bb) != bb_set.end()) {
		return path_info_set;
	}
	bb_set.insert(bb);

	if (device_info_.bb_path_map.find(bb) != device_info_.bb_path_map.end()) {
		return device_info_.bb_path_map[bb];
	}

	PathInfo path_info;
	if (device_info_.bb_ops_map.find(bb) != device_info_.bb_ops_map.end()) {
		path_info = std::to_string(device_info_.bb_num_map[bb]) + " ";
	}

	auto *terminator = bb->getTerminator();
	assert(terminator);
	auto num_of_successors = terminator->getNumSuccessors();
	for (int i = 0; i < num_of_successors; ++i) {
		auto successor = terminator->getSuccessor(i);
		bool bb_in_path = (path_info.find(std::to_string(device_info_.bb_num_map[successor])) != path_info.npos);
		if (!bb_in_path) {
			auto succ_path_info_set = AnalyzePath(successor, bb_set);
			for (auto &succ_path_info: succ_path_info_set) {
				path_info_set.insert(path_info + succ_path_info);
			}
		}
	}
	if (path_info_set.empty() && !path_info.empty()) {
		path_info_set.insert(path_info);
	}
	device_info_.bb_path_map[bb] = path_info_set;
	bb_set.erase(bb);

	return path_info_set;
}

bool DMAAnalysisPass::AnalyzePath(llvm::Function *func) {
	if (!func) {
		return false;
	}

	FunctionInfo func_info = {func};
	std::set<llvm::BasicBlock *> bb_set;
	func_info.paths = AnalyzePath(&func->getEntryBlock(), bb_set);
	func_info.paths.erase(PathInfo{});
	if (!func_info.paths.empty()) {
		device_info_.func_infos.push_back(func_info);
		device_info_.path_num += func_info.paths.size();
	}

	return true;
}

void DMAAnalysisPass::AnalyzeFunc(llvm::Function *func) {
	if (device_info_.visited_funcs.find(func) != device_info_.visited_funcs.end()) {
		return;
	}
	device_info_.visited_funcs.insert(func);
	device_info_.funcs.insert(func);

	for (auto &bb: *func) {
		AnalyzeBB(&bb);
	}

	return;
}

llvm::Function* DMAAnalysisPass::FindPCIProbe() {
	bool is_usb = false;
	llvm::Function *probe_func = NULL;

	for (auto &func: *module_) {
		auto func_name = func.getName().str();
		if (func_name.compare("usb_hcd_pci_probe")) {
			continue;
		}

		is_usb = true;
		probe_func = &func;
	}

	auto *driver_struct = FindDriver();
	if (!driver_struct) {
		SPDLOG_ERROR("Cannot find the device driver structure!");
		return NULL;
	}
	int func_pos = -1;
	if (device_info_.device_type == k_PCI) {
		func_pos = 3;
	} else if (device_info_.device_type == k_PLATFORM) {
		func_pos = 0;
	}
	assert(func_pos != -1);
	if (!is_usb) {
		probe_func = llvm::dyn_cast<llvm::Function>(driver_struct->getAggregateElement(func_pos));
	}
	assert(probe_func);
	for (int i = 3; i <= 7; ++i) {
		auto *func = llvm::dyn_cast<llvm::Function>(driver_struct->getAggregateElement(i));
		if (func) {
			device_info_.state_func.insert(func);
		}
	}
	if (driver_struct->getNumOperands() > 14) {
		auto *device_driver = llvm::dyn_cast<ConstantStruct>(driver_struct->getAggregateElement(14));
		if (device_driver) {
			device_driver->getAggregateElement(16);
			auto *pm_constant = llvm::dyn_cast<Constant>(device_driver->getAggregateElement(16));
			auto *pm_struct = llvm::dyn_cast<ConstantStruct>(pm_constant->getOperand(0));
			if (pm_struct) {
				for (const auto &op: pm_struct->operands()) {
					auto *func = llvm::dyn_cast<llvm::Function>(op);
					if (func) {
						device_info_.state_func.insert(func);
					}
				}
			}
		}
	}

	return probe_func;
}

llvm::ConstantStruct *DMAAnalysisPass::FindDriver() {
    llvm::ConstantStruct *driver_struct = NULL;
    auto &global_list = module_->getGlobalList();

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
        if (device_info_.device_type == k_PCI && driver_struct) {
            return driver_struct;
        }
    }

    return driver_struct;
}

uint64_t DMAAnalysisPass::IsDMA(llvm::Instruction *inst) {
	uint64_t val = 0xDEADBEEF;
	if (inst && dma_result_.find(inst) != dma_result_.end()) {
		val = 0xd11a;
	}

	// if (!inst->hasMetadata()) {
	// 	return val;
	// }
	// auto &debug_info = inst->getDebugLoc();
	// int line = debug_info.getLine();
	// int col = debug_info.getCol();
	// for (auto &lc: device_info_.dma_vals) {
	// 	if (std::get<0>(lc) != line || std::get<1>(lc) != col) {
	// 		continue;
	// 	}
	// 	val = 0xD11A;
	// 	break;
	// }

	return val;
}

uint64_t DMAAnalysisPass::FindOpid(const llvm::Instruction *val) {
	uint64_t op_id = -1;
	for (auto &item: device_info_.ops) {
		if (item.operation.call_inst == val) {
			op_id = item.operation.id;
		}
	}
	return op_id;
}

IntraDepNodePtr DMAAnalysisPass::GetRegValue(llvm::Value *value) {
	bool insert_flag = true;
	IntraDepNodePtr node_ptr;
    IntraDepNodePtr root = std::make_shared<IntraDepNode>(0, 0, k_NODE_VALUE_NUM_TYPE);

    auto *source = GetSourcePointer(value);
	if (device_info_.val2node_map.find(source) != device_info_.val2node_map.end()) {
		auto &ptr = device_info_.val2node_map[source];
		if (ptr->node_value_type != k_NODE_VALUE_CONSTANT) {
			root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_COMMON;
			root->var_cnt = ptr->var_cnt;
			return root;
		}
	}

	if (device_info_.visited_reg_values.find(source) != device_info_.visited_reg_values.end()) {
		//FIXME
        root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_CONSTANT;
        root->value = 0x0;
		return root;
	}
	device_info_.visited_reg_values.insert(source);

    if (auto *constant_int = llvm::dyn_cast<llvm::ConstantInt>(source)) {
        root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_CONSTANT;
        root->value = constant_int->getZExtValue();
		insert_flag = false;
	} else if (auto *argument = llvm::dyn_cast<llvm::Argument>(source)) {
        root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_ARG;
		auto *pag_node = device_info_.svf_pag->getGNode(device_info_.svf_pag->getValueNode(source));
		auto *vfg_node = device_info_.svf_vfg->getDefVFGNode(pag_node);
		std::unordered_set<llvm::Value*> addedValues;
		std::unordered_set<uint64_t> addedInts;
		for (auto &in_edge: vfg_node->getInEdges()) {
			auto *val = const_cast<llvm::Value*>(in_edge->getSrcNode()->getValue());
			node_ptr = GetRegValue(val);
			root->addChild(std::move(node_ptr));
		}
		if (!root->ChildrenSize()) {
			root->node_value_type = k_NODE_VALUE_NUM_TYPE;
		}
    } else if (auto *inst = llvm::dyn_cast<llvm::Instruction>(source)) {
		SVF::SVFVar *pag_node;
		const SVF::SVFGNode *vfg_node;
		uint64_t op_id;
		bool flag = false;

        switch (inst->getOpcode()) {
			case Instruction::Add:
			case Instruction::Alloca:
			case Instruction::GetElementPtr:
				SPDLOG_INFO("{}: Do not care inst: {}", __FUNCTION__, LLVMPrint(inst));
				break;
            case Instruction::Call:
                root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_CALL;
				op_id = FindOpid(inst);
				if (op_id != -1) {
					root->value = op_id;
				} else {
					SPDLOG_INFO("{}: Cannot find the call: {}", __FUNCTION__, LLVMPrint(inst));
					root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_NUM_TYPE;
				}
                break;
            case Instruction::Or:
                root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_OR;
                for (auto &user : inst->operands()) {
					node_ptr = GetRegValue(user);
					root->addChild(std::move(node_ptr));
                }
                break;
            case Instruction::And:
                root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_AND;
                for (auto &user : inst->operands()) {
					node_ptr = GetRegValue(user);
					root->addChild(std::move(node_ptr));
                }
                break;
            case Instruction::Shl:
                root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_SHL;
                for (auto &user : inst->operands()) {
					node_ptr = GetRegValue(user);
					root->addChild(std::move(node_ptr));
                }
                break;
            case Instruction::LShr:
                root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_LSHR;
                for (auto &user : inst->operands()) {
					node_ptr = GetRegValue(user);
					root->addChild(std::move(node_ptr));
                }
                break;
			case Instruction::PHI:
                root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_PHI;
                for (auto &user : inst->operands()) {
					node_ptr = GetRegValue(user);
					root->addChild(std::move(node_ptr));
                }
                break;
			case Instruction::Select:
                root->node_value_type = IntraDepNodeValueType::k_NODE_VALUE_SELECT;
				for (auto user = inst->op_begin() + 1; user != inst->op_end(); ++user) {
					node_ptr = GetRegValue(llvm::dyn_cast<llvm::Value>(user));
					root->addChild(std::move(node_ptr));
                }
                break;
            default:
				SPDLOG_WARN("{}: Unhandled instruction opcode: {}", __FUNCTION__, LLVMPrint(inst));
        }
    } else {
		SPDLOG_WARN("{}: Unhandled value type.", __FUNCTION__);
    }

	if (insert_flag) {
		device_info_.val2node_map.insert({source, root});
		root->var_cnt = device_info_.val2node_map.size();
	}
	device_info_.visited_reg_values.erase(source);
	// root->replaceRootWithFirstChild();

	// root->printNodeTree();

    return root;
}

uint64_t DMAAnalysisPass::GetValue(llvm::Value *value) {
	uint64_t val = IsDMA(llvm::dyn_cast<llvm::Instruction>(value));
	if (val != 0xDEADBEEF) {
		return val;
	}

	auto *source = GetSourcePointer(value);

	auto *add_inst = llvm::dyn_cast<llvm::BinaryOperator>(source);
	if (auto *constant_int = llvm::dyn_cast<llvm::ConstantInt>(source)) {
		val = constant_int->getZExtValue();
	} else if (add_inst && add_inst->getOpcode() == llvm::Instruction::BinaryOps::Add) {
		val = GetValue(add_inst->getOperand(1));
	} else {
		std::stack<const SVF::VFGNode *> vfg_stack;
		FindSource(source, vfg_stack);
		auto vfg_node = vfg_stack.top();
		auto *pag_node = device_info_.svf_vfg->getLHSTopLevPtr(vfg_node);
		if (!pag_node->hasValue()) {
			return val;
		}
		auto *node_value = pag_node->getValue();
		for (auto user: node_value->users()) {
			auto *store_inst = llvm::dyn_cast<llvm::StoreInst>(user);
			if (!store_inst) {
				continue;
			}
			auto *store_op = store_inst->getOperand(0);
			if (auto *constant_int = llvm::dyn_cast<llvm::ConstantInt>(store_op)) {
				val = constant_int->getZExtValue();
			}
		}
	}

	return val;
}

uint64_t DMAAnalysisPass::MatchIO(const llvm::Value *val, struct IOInfo &target_io_info) {
	uint64_t id = 0;
	for (auto io_info: device_info_.io_info) {
		if (io_info.is_mmio == false &&
				io_info.device_type == target_io_info.device_type &&
				io_info.offset == target_io_info.offset) {
				id = io_info.region_id;
				break;
		}
	}
	for (auto &io_info: device_info_.io_info) {
		if (io_info.is_mmio == false) {
			continue;
		}
		// if (io_info.device_type != target_io_info.device_type) {
		// 	continue;
		// }
		for (auto byte1: io_info.bytes) {
			for (auto byte2: target_io_info.bytes) {
				if (byte1 == byte2) {
					id = io_info.region_id;
					io_info.var.insert(val);
					break;
				}
			}
		}
	}

	return id;
}

const llvm::Value* DMAAnalysisPass::GetOffset(llvm::Value *val, std::set<uint64_t> &reg, bool is_io) {
	auto *pag_node = device_info_.svf_pag->getGNode(
	device_info_.svf_pag->getValueNode(val));
	auto *vfg_node = device_info_.svf_vfg->getDefVFGNode(pag_node);
	auto *curr_node = vfg_node;
	auto *curr_value = device_info_.svf_vfg->getLHSTopLevPtr(curr_node)->getValue();
	uint64_t depth = 0;
	SVF::FILOWorkList<const SVF::VFGNode *> work_list;
	work_list.push(vfg_node);
	
	while (!work_list.empty()) {
		if (depth++ > 50) {
			break;
		}
		curr_node = work_list.pop();
		auto pag_node = device_info_.svf_vfg->getLHSTopLevPtr(curr_node);
		if (!pag_node->hasValue()) {
			break;
		}
		curr_value = pag_node->getValue();
		auto *add_inst = llvm::dyn_cast<llvm::BinaryOperator>(curr_value);
		auto *gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(curr_value);
		if (is_io && add_inst && add_inst->getOpcode() == llvm::Instruction::BinaryOps::Add) {
			reg.insert(GetValue(add_inst->getOperand(1)));
		} else if (!is_io && gep_inst) {
			auto source_type = gep_inst->getSourceElementType();
			auto name = gep_inst->getOperand(0)->getName().str();
			auto *value_name = gep_inst->getOperand(0)->getValueName();
			if (source_type->isStructTy()) {
				reg.insert(CalOffset(gep_inst));
			} else if (source_type->isIntegerTy()) {
				reg.insert(GetValue(gep_inst->idx_begin()->get()));
			} else {
				SPDLOG_ERROR("Cannot handle type in {} {}", __FUNCTION__, LLVMPrint(source_type));
			}
		} else if (auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(curr_value)) {
			break;
		}

		if (curr_node->hasIncomingEdge()) {
			auto *in_edge = *curr_node->InEdgeBegin();
			work_list.push(in_edge->getSrcNode());
		}
	}
	
	if (reg.empty()) {
		reg.insert(0);
	}

	return curr_value;
}

uint64_t DMAAnalysisPass::MatchIOVar(const llvm::Value *val) {
	uint8_t region_id = 0;

	for (auto &io_info: device_info_.io_info) {
		if (io_info.var.find(val) != io_info.var.end()) {
			region_id = io_info.region_id;
			break;
		}
	}

	return region_id;
}

std::set<uint64_t> DMAAnalysisPass::GetReg(llvm::Value *value, uint64_t &region_id, bool is_io) {
	std::set<uint64_t> reg;
	
	if (auto *constant_int = llvm::dyn_cast<llvm::ConstantInt>(value)) {
		reg.insert(constant_int->getZExtValue());
	} else {
		struct IOInfo io_info;
		auto *base = GetOffset(value, reg, is_io);

		auto *source = GetSourcePointer(value);
		auto *gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(source);
		if (gep_inst) {
			auto *source_element_type = gep_inst->getSourceElementType();
			if (source_element_type->isStructTy()) {
				auto struct_name = source_element_type->getStructName().str();
				for (const auto &entry: default_region_name_id) {
					if (struct_name.find(std::get<0>(entry)) != std::string::npos) {
						region_id = std::get<1>(entry);
						break;
					}
				}
			}
		}

		if (!region_id) {
			region_id = MatchIOVar(base);
		}
		if (!region_id) {
			GetIOInfo(base, io_info.bytes);
			region_id = MatchIO(base, io_info);
		}
		if (!region_id) {
			uint64_t mmio_region_num = 0;
			uint64_t mmio_region_id = 0;
			for (auto &io_info: device_info_.io_info) {
				if (io_info.is_mmio == false) {
					continue;
				}
				mmio_region_num++;
				mmio_region_id = io_info.region_id;
			}
			if (mmio_region_num == 1) {
				region_id = mmio_region_id;
			}
		}
		// if (!region_id && !is_io) {
		// 	reg.clear();
		// }
	}

	if (reg.empty() && !is_io) {
		reg.insert(0xDEADC0DE);
	}

	return reg;
}

uint64_t DMAAnalysisPass::CalOffset(const llvm::GetElementPtrInst *gep_inst) {
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

std::string DMAAnalysisPass::Type2Str(llvm::Type *type) {
	std::string type_name;

	if (type->isStructTy()) {
		type_name = type->getStructName().str();
	} else {
		type_name = LLVMPrint(type);
	}

	return type_name;
}

bool DMAAnalysisPass::ExtractInt(const llvm::GetElementPtrInst *gep_inst,
		std::vector<uint64_t> &offset) {
	for (auto idx = gep_inst->idx_begin(); idx != gep_inst->idx_end(); ++idx) {
		auto gep_offset = idx->get();
		offset.push_back(GetValue(gep_offset));
	}

	return true;
}

const llvm::Value* DMAAnalysisPass::FindSource(const llvm::Value *val, std::stack<const SVF::VFGNode *> &vfg_stack) {
	auto *pag_node = device_info_.svf_pag->getGNode(
			device_info_.svf_pag->getValueNode(val));
	auto *vfg_node = device_info_.svf_vfg->getDefVFGNode(pag_node);
	auto *curr_node = vfg_node;
	uint64_t depth = 0;
	vfg_stack.push(curr_node);
	
	while (!vfg_stack.empty()) {
		if (depth++ > 50) { // Avoid infinite loop
			break;
		}
		vfg_stack.push(curr_node);
		if (!curr_node->hasIncomingEdge()) {
			auto *pag_node = device_info_.svf_vfg->getLHSTopLevPtr(curr_node);
			if (!pag_node->hasValue()) {
				break;
			}
			auto *svf_val = pag_node->getValue();
			return svf_val;
		} else {
			auto *in_edge = *curr_node->InEdgeBegin();
			curr_node = in_edge->getSrcNode();
		}
	}

	return NULL;
}

void DMAAnalysisPass::GetAliasPointers(llvm::Value *val,
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

void DMAAnalysisPass::PreProcess() {
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

void DMAAnalysisPass::writeToFile(const std::string& filename, const std::string& data) {
    std::ofstream out(filename, std::ios::binary);
    out.write(data.data(), data.size());
    out.close();
}

void DMAAnalysisPass::WriteResult() {
	// YAML::Emitter out;
	// out << device_info_;

	// std::fstream result{result_yaml, std::ios::out};
	// result << out.c_str();
	// result.close();
	//
	std::filesystem::path bin_path(result_bin.getValue());
    std::filesystem::path parent_dir = bin_path.parent_path();

    // Extract the filename without extension
    std::string filename = result_bin;

    // Create filenames for text and JSON by replacing "bin" with "txt" and "json"
    std::filesystem::path text_filename = parent_dir / (filename.replace(filename.find("bin"), 3, "txt"));
    std::filesystem::path json_filename = parent_dir / (filename.replace(filename.find("txt"), 3, "json"));

	Device protoDevice;
    serializeDeviceInfo(device_info_, &protoDevice);

    // Binary format
    std::string binaryOutput;
    protoDevice.SerializeToString(&binaryOutput);
    writeToFile(result_bin, binaryOutput);

    // Text format
    std::string textOutput;
    google::protobuf::TextFormat::PrintToString(protoDevice, &textOutput);
    writeToFile(text_filename, textOutput);

    // JSON format
    std::string jsonOutput;
    google::protobuf::util::MessageToJsonString(protoDevice, &jsonOutput);
    writeToFile(json_filename, jsonOutput);
}

void DMAAnalysisPass::serializeIntraDepNode(const IntraDepNodePtr& node, device::IntraDepNode* protoNode) {
    protoNode->set_value(node->value);
    protoNode->set_var_cnt(node->var_cnt);
    protoNode->set_node_value_type(static_cast<device::IntraDepNodeValueType>(node->node_value_type));
    for (const auto& child : node->children) {
        serializeIntraDepNode(child, protoNode->add_children());
    }
}

void DMAAnalysisPass::serializeOperation(const Operation& op, device::Operation* protoOp) {
    protoOp->set_type(op.op_type);
    protoOp->set_rw(op.op_rw);
    protoOp->set_name(op.name);
    protoOp->set_size(op.size);
    protoOp->set_region_id(op.region_id);
    for (auto reg : op.reg) {
        protoOp->add_reg(reg);
    }
    if (op.reg_node) {
        serializeIntraDepNode(op.reg_node, protoOp->mutable_reg_node());
    }
}

void DMAAnalysisPass::serializeIO(const IOInfo& io, device::IO* protoIO) {
    protoIO->set_mmio(io.is_mmio);
    protoIO->set_id(io.region_id);
    protoIO->set_source_type(io.device_type);
    for (auto offset : io.offset) {
        protoIO->add_offset(offset);
    }
    for (auto bytes : io.bytes) {
        protoIO->add_bytes(bytes);
    }
}

void DMAAnalysisPass::serializeBasicBlocks(const DeviceInfo& device_info, google::protobuf::Map<std::string, std::string>* protoBBs) {
    std::vector<std::pair<const llvm::BasicBlock*, uint64_t>> vec(device_info.bb_num_map.begin(), device_info.bb_num_map.end());
    std::sort(vec.begin(), vec.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
    });

    for (const auto& item : vec) {
        auto it = device_info.bb_ops_map.find(item.first);
        if (it == device_info.bb_ops_map.end() || it->second.empty()) {
            continue;
        }

        std::string bbName = item.first->getParent()->getName().str() + "_" + std::to_string(item.second);

        std::string ops;
        for (const auto& op : it->second) {
            ops += std::to_string(op) + " ";
        }

        (*protoBBs)[bbName] = ops;
    }
}

bool function_compare(const FunctionInfo& a, const FunctionInfo& b) {
    return a.func->getName().str() < b.func->getName().str();
}

void DMAAnalysisPass::serializeFuncs(const std::vector<FunctionInfo>& func_infos, google::protobuf::Map<std::string, device::Function>* protoFuncs) {
    // Create a sorted copy of the function info vector
    std::vector<FunctionInfo> sorted_funcs = func_infos;
    std::sort(sorted_funcs.begin(), sorted_funcs.end(), function_compare);

    // Iterate over the sorted functions
    for (const auto& func : sorted_funcs) {
        // Skip functions with empty paths
        if (func.paths.empty()) {
            continue;
        }

        // Create a Function message to hold the paths
        device::Function protoFunc;
        int i = 0;

        // Populate the paths map in the Function message
        for (const auto& path_info : func.paths) {
            (*protoFunc.mutable_paths())[i++] = path_info;  // Assuming path_info is a string, adjust as necessary
        }

        // Add the Function message to the protoFuncs map with the function name as the key
        (*protoFuncs)[func.func->getName().str()] = protoFunc;
    }
}

void DMAAnalysisPass::serializeCallee(llvm::Function* callee, device::Callee* protoCallee) {
    protoCallee->set_name(callee->getName().str());
    protoCallee->set_num_args(callee->arg_size());
    protoCallee->set_return_type(callee->getReturnType()->getTypeID());
}

void DMAAnalysisPass::serializeCalleeOrOp(const CalleeOrOp& calleeOrOp, device::CalleeOrOp* protoCalleeOrOp) {
	protoCalleeOrOp->set_id(calleeOrOp.id);
    if (calleeOrOp.kind == calleeOrOp.IsCallee) {
        auto* protoCallee = protoCalleeOrOp->mutable_callee();
        serializeCallee(calleeOrOp.callee, protoCallee);
    } else {
        auto* protoOp = protoCalleeOrOp->mutable_operation();
        serializeOperation(calleeOrOp.operation, protoOp);
    }
}

void DMAAnalysisPass::serializeDeviceInfo(const DeviceInfo& device_info, Device* protoDevice) {
    protoDevice->set_device_name(device_info.device_name);
    protoDevice->set_region_num(device_info.io_region_num);
    protoDevice->set_dma_num(device_info.dma_info.size());
    protoDevice->set_func_num(device_info.func_infos.size());
    protoDevice->set_bb_num(device_info.bb_ops_map.size());
    protoDevice->set_op_num(device_info.ops.size());
    protoDevice->set_unique_op_num(device_info.unique_ops);
    protoDevice->set_path_num(device_info.path_num);
    protoDevice->set_intra_num(device_info.intra_num);

	for (const auto &func: device_info_.state_func) {
		protoDevice->add_states(func->getName().str());
	}
	protoDevice->set_state_num(device_info_.state_func.size());

	for (const auto& op : device_info.ops) {
        auto* protoCalleeOrOp = protoDevice->add_ops();
        serializeCalleeOrOp(op, protoCalleeOrOp);
    }

	serializeBasicBlocks(device_info, protoDevice->mutable_bb());

    for (const auto& probe : device_info.probe_func) {
        protoDevice->add_probe(probe->getName().str());
    }

    if (device_info.int_func) {
        protoDevice->set_interrupt(device_info.int_func->getName().str());
    }

    for (const auto& entry : device_info.entries) {
        protoDevice->add_entries(entry->getName().str());
    }

    for (const auto& io : device_info.io_info) {
        auto* protoIO = protoDevice->add_io();
        serializeIO(io, protoIO);
    }

    serializeFuncs(device_info.func_infos, protoDevice->mutable_funcs());

	// for (const auto& dma : device_info.dma_info) {
    //     auto* protoDMA = protoDevice->add_dma();
    //     serializeDMAInfo(dma, protoDMA);
    // }

    // serializeDMAValues(device_info.dma_vals, protoDevice->mutable_dma_vals());
}

void DMAAnalysisPass::CleanUp() {
	delete device_info_.svf_vfg;
	SVF::AndersenWaveDiff::releaseAndersenWaveDiff();
	SVF::SVFIR::releaseSVFIR();
	SVF::LLVMModuleSet::releaseLLVMModuleSet();
}

char DMAAnalysisPass::ID = 0;
static llvm::RegisterPass<DMAAnalysisPass> X("dma-analysis-pass", "DMA Pass", false, true);
}
