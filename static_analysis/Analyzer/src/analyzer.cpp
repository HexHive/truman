#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "common.h"
#include "yaml-cpp/node/parse.h"
#include "yaml-cpp/yaml.h"
#include <tuple>

#include "analysis.h"
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

#define NETDEV_IOCTL "NETDEV_IOCTL"
#define READ_HDR "READ_HDR"
#define WRITE_HDR "WRITE_HDR"
#define IOCTL_HDR "IOCTL_HDR"
#define DEVATTR_SHOW "DEVSHOW"
#define DEVATTR_STORE "DEVSTORE"
#define V4L2_IOCTL_FUNC "V4IOCTL"
#define NULL_ARG "NULL_ARG"
#define MY_IOCTL "MY_IOCTL"

std::map<Value *, std::set<PointerPointsTo*>*> GlobalState::globalVariables;
std::map<Function *, std::set<BasicBlock*>*> GlobalState::loopExitBlocks;

FunctionHandlerCallback* AliasAnalysisVisitor::callback = new AliasFuncHandlerCallback();
FunctionHandler* AliasAnalysisVisitor::functionHandler = new FunctionHandler(new KernelFunctionChecker());
FunctionChecker* TaintAnalysisVisitor::functionChecker = nullptr;

static cl::opt<std::string> checkFunctionName("toCheckFunction",
											cl::desc("Function which is to be considered as entry point "
															"into the driver"),
											cl::value_desc("full name of the function"), cl::init(""));

static cl::opt<std::string> functionType("functionType",
											cl::desc("Function Type. \n Linux kernel has different "
															"types of entry points from user space.\n"
															"Specify the type of entry function."),
											cl::value_desc("Function Type"), cl::init(""));

static cl::opt<unsigned> skipInit("skipInit", cl::desc("Skip analyzing init functions."),
									cl::value_desc("long, non-zero value indicates, skip initialization function"),
									cl::init(1));

// static cl::opt<std::string> outputFile("outputFile",
// 										cl::desc("Path to the output file, where all the warnings should be stored."),
// 										cl::value_desc("Path of the output file."), cl::init(""));

static cl::opt<std::string> instrWarnings("instrWarnings",
											cl::desc("Path to the output file, where all the warnings w.r.t instructions should be stored."),
											cl::value_desc("Path of the output file."), cl::init(""));

static cl::opt<std::string> entryConfig("entryConfig",
											cl::desc("Config file that specifies all entry functions to be analyzed and the related information like type and user arg"),
											cl::value_desc("The path of the config file"), cl::init(""));

// static cl::opt<std::string> dmaYaml("dmaYaml",
// 											cl::desc("Yaml file that specifies all DMA related functions to be analyzed and the related information like type and user arg"),
// 											cl::value_desc("The path of the yaml file"), cl::init(""));

static cl::opt<bool> allFunc("allFunc", cl::desc("allFunc"), cl::value_desc("allFunc"), cl::init(""));

static std::vector<FuncInf*> targetFuncs;

void AnalysisPass::setupGlobals(Module &m) {
	// Setup global variables.
	// Map that contains global variables to AliasObjects.
	std::map<llvm::Value *, AliasObject *> global_object_cache;
	std::vector<llvm::GlobalVariable *> visitor_cache;
	visitor_cache.clear();
	// First add global functions.
	for (auto mi = m.begin(); mi != m.end(); ++mi) {
		GlobalState::addGlobalFunction(&(*mi), global_object_cache);
	}
	auto &curr_global_list = m.getGlobalList();
	for (auto gstart = curr_global_list.begin(); gstart != curr_global_list.end(); ++gstart) {
		// We cannot simply ignore the constant global structs (e.g. some "ops" structs are constant, but we still need
		// to know their field function pointers to resolve the indirect call sites involving them).
		/*
		// ignore constant immutable global pointers
		if((*gstart).isConstant()) {
			continue;
		}
		*/
		if (!GlobalState::toCreateObjForGV(&(*gstart))) {
			continue;
		}
		GlobalState::addGlobalVariable(visitor_cache, &(*gstart), global_object_cache);
		assert(visitor_cache.empty());
	}
	global_object_cache.clear();

	// OK get loop info of all the functions and store them for future use.
	// Get all loop exit basic blocks.
	for (auto mi = m.begin(); mi != m.end(); ++mi) {
		auto &curr_func = *mi;
		if (curr_func.isDeclaration()) {
			continue;
		}
		auto &p = getAnalysis<LoopInfoWrapperPass>(curr_func);
		LoopInfo &func_loop_info = p.getLoopInfo();
		llvm::SmallVector<llvm::BasicBlock *, 1000> all_exit_bbs;
		all_exit_bbs.clear();
	}
}

// Try to set all global variables as taint source.
void AnalysisPass::addGlobalTaintSource(GlobalState &target_state) {
	// Type of globalVariables: std::map<llvm::Value *, std::set<PointerPointsTo*> *>
	for (auto const &it: GlobalState::globalVariables) {
		auto *v = it.first;
		auto *ps = it.second;
		if (!v || !ps || ps->empty()) {
			continue;
		}
		auto *gv = llvm::dyn_cast<GlobalVariable>(v);
		if (gv && gv->isConstant()) {
			continue;
		}
		if (v->getType() && v->getType()->isPointerTy()) {
			auto *ty = v->getType()->getPointerElementType();
			// Exclude certain types, e.g., function.
			if (ty->isFunctionTy() || ty->isLabelTy() || ty->isMetadataTy()) {
				continue;
			}
		}

		auto *loc = new InstLoc(v, nullptr);
		for (auto const &p: *ps) {
			if (!p->targetObject) {
				continue;
			}
			// Exclude the const object.
			if (p->targetObject->is_const) {
				continue;
			}
			p->targetObject->setAsTaintSrc(loc, true);
		}
	}
}

//Copied from online source...
std::vector<std::string> AnalysisPass::split(const std::string& str, const std::string& delim) {
	std::vector<std::string> tokens;
	size_t prev = 0, pos = 0;
	do {
		pos = str.find(delim, prev);
		if (pos == std::string::npos) {
			pos = str.length();
		}
		std::string token = str.substr(prev, pos-prev);
		if (!token.empty()) {
			tokens.push_back(token);
		}
		prev = pos + delim.length();
	} while (pos < str.length() && prev < str.length());
	return tokens;
}

Function *AnalysisPass::getFuncByName(Module &m, std::string &name) {
	for (auto &f: m) {
		if (f.hasName() && f.getName().str() == name) {
			return &f;
		}
	}
	return nullptr;
}

// void getDMAVals(GlobalState &global_state) {
// 	auto yaml = YAML::LoadFile(dmaYaml);
// 	for (auto seq: yaml) {
// 		for (auto dev: seq) {
// 			for (auto item: dev.second) {
// 				auto item_name = item.first.as<std::string>();
// 				if (item_name.compare("DMA Val")) {
// 					continue;
// 				}
// 				auto dma_vals = item.second;
// 				for (auto dma_val: dma_vals) {
// 					auto debug_info = dma_val.as<std::string>();
// 					std::stringstream stream(debug_info);
// 					std::string line, col;
// 					getline(stream, line, ' ');
// 					getline(stream, col, ' ');
// 					global_state.dma_vals.insert(
// 						std::make_tuple(std::stoi(line), std::stoi(col)));
// 				}
// 			}
// 		}
// 	}
// }

void AnalysisPass::getTargetFunctions(llvm::Module &m) {
	if (allFunc) {
		// for (auto &f: m) {
		// 	if (f.isDeclaration()) {
		// 		continue;
		// 	}
		// 	auto func_name = f.getName();
		// 	if (!func_name.contains("probe")) {
		// 		continue;
		// 	}
		// 	auto *fi = new FuncInf();
		// 	fi->name = f.getName().str();
		// 	fi->func = &f;
		// 	targetFuncs.push_back(fi);
		// }
		for (auto &global: m.globals()) {
			if (global.hasExternalLinkage()) {
				continue;
			}
			auto p_type = global.getType();
			if (!p_type->isPointerTy()) {
				continue;
			}
			auto type = p_type->getContainedType(0);
			if (!type->isStructTy()) {
				continue;
			}
			auto type_name = type->getStructName();
			if (type_name.contains("ops") || !type_name.compare("struct.pci_driver") ||
				!type_name.contains("struct.hc_driver")) {
				auto *init = global.getInitializer();
				for (auto &item: init->operands()) {
					auto *func = llvm::dyn_cast<llvm::Function>(item);
					if (!func) {
						continue;
					}
					auto *fi = new FuncInf();
					fi->name = func->getName().str();
					fi->func = func;
					targetFuncs.push_back(fi);
				}
			}
		}
		// for (auto &func: m) {
		// 	if (func.isDeclaration()) {
		// 		continue;
		// 	}
		// 	auto func_name = func.getName();
		// 	if (func_name.contains("probe")) {
		// 		continue;
		// 	}
		// 	auto *fi = new FuncInf();
		// 	fi->name = func.getName().str();
		// 	fi->func = &func;
		// 	targetFuncs.push_back(fi);
		// }
	} else if (checkFunctionName.size() > 0) {
		// Method 0: specify a single entry function.
		auto *fi = new FuncInf();
		fi->name = checkFunctionName;
		fi->func = getFuncByName(m, checkFunctionName);
		// The user arg number might be encoded in the type string if it's MY_IOCTL.
		if (functionType.find(MY_IOCTL) == 0) {
			fi->ty = MY_IOCTL;
			// Get the encoded user arg information.
			auto tks = split(functionType, "_");
			if (tks.size() > 2) {
				for (int i = 2; i < tks.size(); ++i) {
					// NOTE: Exceptions may occur if the invalid arg is passed-in.
					int idx = std::stoi(tks[i]);
					fi->user_args.push_back(idx);
				}
			}
		} else {
			fi->ty = functionType;
		}
		targetFuncs.push_back(fi);
	} else if (entryConfig.size() > 0) {
		//Method 1: specify one or multiple functions in a config file, together w/ related information like type.
		//Line format:
		//<func_name> <type> <user_arg_no e.g. 1_3_6>, or
		//* opt opt_arg0 opt_arg1 ...
		std::ifstream ifile;
		ifile.open(entryConfig);
		std::string l;
		while (std::getline(ifile, l)) {
			//Skip the comment line
			if (l.find("#") == 0) {
				continue;
			}
			std::vector<std::string> tks = split(l," ");
			if (tks.size() < 2) {
				dbgs() << "Invalid line in the entry config file: " << l << "\n";
				continue;
			}
			if (tks[0] == "*") {
				//An option line.
				if (tks[1] == "XENTRY_SHARED_OBJ") {
					DRCHECKER::enableXentryImpObjShare = true;
					for (int i = 2; i < tks.size(); ++i) {
						DRCHECKER::sharedObjTyStrs.insert(tks[i]);
					}
				}else {
					//The option is not supported.
					dbgs() << "Unrecognized option: " << l << "\n";
				}
				continue;
			}
			FuncInf *fi = new FuncInf();
			fi->name = tks[0];
			fi->func = getFuncByName(m,tks[0]);
			fi->ty = tks[1];
			if (tks.size() > 2) {
				//Get the user arg indices.
				std::vector<std::string> utks = split(tks[2],"_");
				for (std::string &s : utks) {
					int idx = std::stoi(s);
					fi->user_args.push_back(idx);
				}
			}
			targetFuncs.push_back(fi);
		}
		ifile.close();
	} else {
		// No entry functions specified.
		llvm::dbgs() << "getTargetFunctions(): No entry functions specified!\n";
		return;
	}
	// debug output
	llvm::dbgs() << "getTargetFunctions: Functions to analyze:\n";
	for (FuncInf *fi : targetFuncs) {
		llvm::dbgs() << "FUNC: " << fi->name << " PTR: " << (const void*)fi->func << " TYPE: " << fi->ty << " USER_ARGS:";
		for (int i : fi->user_args) {
			llvm::dbgs() << " " << i;
		}
		llvm::dbgs() << "\n";
	}

	return;
}

void AnalysisPass::setupArgs(FuncInf *fi, GlobalState &target_state, std::vector<Instruction *> *call_sites) {
	if (!fi || !fi->func) {
		return;
	}
	target_state.getOrCreateContext(call_sites);
	auto func = fi->func;
	auto *arg = func->getArg(1);
	auto *phy_dma_addr = InstructionUtils::stripAllCasts(llvm::dyn_cast<llvm::Value>(arg), true);
	auto *loc = new InstLoc(phy_dma_addr, call_sites);
	auto *curr_tag = new TaintTag(0, phy_dma_addr, false);
	auto *curr_flag = new TaintFlag(loc, true, curr_tag);
	auto *curr_taint_info = new std::set<TaintFlag*>();
	curr_taint_info->insert(curr_flag);
	TaintUtils::updateTaintInfo(target_state, call_sites, phy_dma_addr, curr_taint_info);
	return;

	// target_state.getOrCreateContext(call_sites);
	// auto *curr_points_to = target_state.getPointsToInfo(call_sites);
	// auto *ei = fi->func->getEntryBlock().getFirstNonPHI();
	// auto *ctx = new std::vector<Instruction *>();
	// ctx->push_back(ei);
	// auto *loc = new InstLoc(ei, ctx);
	// unsigned long arg_no = 0;
	// for (auto arg_begin = fi->func->arg_begin();
	// 	arg_begin != fi->func->arg_end(); ++arg_begin) {
	// 	llvm::Value *curr_arg = &(*arg_begin);
	// 	auto *arg_type = curr_arg->getType();
	// 	// Type *arg_type = nullptr;
	// 	// if (InstructionUtils::isPrimitivePtr(curr_arg->getType()) ||
	// 	// 	InstructionUtils::isPrimitiveTy(curr_arg->getType())) {
	// 	// 	arg_type = InstructionUtils::inferPointeeTy(curr_arg);
	// 	// } else if (curr_arg->getType() && curr_arg->getType()->isPointerTy()) {
	// 	// 	arg_type = curr_arg->getType()->getPointerElementType();
	// 	// }
	// 	auto type_name = InstructionUtils::getTypeName(arg_type);
	// 	if (type_name.compare("%struct.net_device*")) {
	// 		continue;
	// 	}
	// 	auto *obj = new FunctionArgument(curr_arg, arg_type, fi->func, call_sites);
	// 	obj->addPointerPointsTo(curr_arg, loc);
	// 	auto *pto = new PointerPointsTo(curr_arg, obj, 0, loc, false);
	// 	if (curr_points_to) {
	// 		if (curr_points_to->find(curr_arg) == curr_points_to->end()) {
	// 			(*curr_points_to)[curr_arg] = new std::set<PointerPointsTo *>();
	// 		}
	// 		(*curr_points_to)[curr_arg]->insert(pto);
	// 	}
	// 	for (auto &entry_arg: target_state.entry_args_set) {
	// 		if (std::get<1>(entry_arg) == obj) {
	// 			// Already set.
	// 			continue;
	// 		}
	// 		if (std::get<0>(entry_arg) == arg_type) {
	// 			// Same name.
	// 			auto *arg = std::get<2>(entry_arg);
	// 			auto *loc = std::get<3>(entry_arg);
	// 			auto *pto = std::get<4>(entry_arg);
	// 			obj->addPointerPointsTo(arg, loc);
	// 			if (curr_points_to) {
	// 				(*curr_points_to)[curr_arg]->insert(pto);
	// 			}
	// 		}
	// 	}
	// 	target_state.entry_args_set.insert(std::make_tuple(arg_type, obj, curr_arg, loc, pto));
	// }
}

void AnalysisPass::setupFunctionArgs(FuncInf *fi, GlobalState &target_state, std::vector<Instruction *> *call_sites) {
	if (!fi || !fi->func) {
		return;
	}
	target_state.getOrCreateContext(call_sites);
	
	// Arguments which are tainted and passed by user
	std::set<unsigned long> tainted_args;
	// Arguments which contain tainted data
	std::set<unsigned long> tainted_arg_data;
	// Arguments which are pointer args
	std::set<unsigned long> pointer_args;
	bool is_handled = false;
	if (fi->ty == IOCTL_HDR) {
		// Last argument is the user pointer.
		tainted_args.insert(fi->func->arg_size() - 1);
		pointer_args.insert(0);
		is_handled = true;
	}
	//hz: We want to set all global variables as taint source,
	//for ioctl() in driver code, the FILE pointer should also
	//be regarded as a global variable.
	if (fi->ty == MY_IOCTL) {
		if (fi->user_args.size() > 0) {
			for (int i: fi->user_args) {
				tainted_args.insert(i);
			}
		} else {
			// by default the last argument is the user pointer.
			tainted_args.insert(fi->func->arg_size() - 1);
		}
		is_handled = true;
	}
	
	if (fi->ty == READ_HDR || fi->ty == WRITE_HDR) {
		tainted_args.insert(1);
		//taintedArgs.insert(2);
		//hz: for now we don't add the args to the "pointerArgs" and create the Arg objects for them, because later in the analysis
		//we will create the objs on demand.
		//pointerArgs.insert(0);
		//pointerArgs.insert(3);
		is_handled = true;
	}

	if (fi->ty == V4L2_IOCTL_FUNC) {
		tainted_arg_data.insert(fi->func->arg_size() - 1);
		for (unsigned long i = 0; i < fi->func->arg_size(); ++i) {
			pointer_args.insert(i);
		}
		is_handled = true;
	}

	if (fi->ty == DEVATTR_SHOW) {
		for (unsigned long i = 0; i < fi->func->arg_size(); ++i) {
			pointer_args.insert(i);
		}
		is_handled = true;
	}

	if (fi->ty == DEVATTR_STORE) {
		if (fi->func->arg_size() == 3) {
			tainted_arg_data.insert(1);
		} else {
			tainted_arg_data.insert(2);
		}
		is_handled = true;
	}

	if (fi->ty == NETDEV_IOCTL) {
		tainted_arg_data.insert(1);
		for (unsigned long i = 0; i < fi->func->arg_size() - 1; ++i) {
			pointer_args.insert(i);
		}
		is_handled = true;
	}

	if (fi->ty == NULL_ARG) {
		is_handled = true;
	}
	assert(is_handled);

	auto *curr_points_to = target_state.getPointsToInfo(call_sites);
	// Create the InstLoc for the function entry.
	llvm::Instruction *ei = fi->func->getEntryBlock().getFirstNonPHIOrDbg();
	auto *ctx = new std::vector<llvm::Instruction *>();
	ctx->push_back(ei);
	auto *loc = new InstLoc(ei, ctx);
	unsigned long arg_no = 0;
	for (auto arg_begin = fi->func->arg_begin();
		arg_begin != fi->func->arg_end(); ++arg_begin) {
		llvm::Value *curr_arg_val = &(*arg_begin);
		if (tainted_args.find(arg_no) != tainted_args.end()) {
			// hz: Add a taint tag indicating that the taint is from user-provided arg, instead of global states.
			// This tag represents the "arg", at the function entry its point-to object hasn't been created yet, so no "pobjs" for the tag.	
			auto *curr_tag = new TaintTag(0, curr_arg_val, false);
			auto *curr_flag = new TaintFlag(loc, true, curr_tag);
			auto *curr_taint_info = new std::set<TaintFlag *>();
			curr_taint_info->insert(curr_flag);
			TaintUtils::updateTaintInfo(target_state, call_sites, curr_arg_val, curr_taint_info);
		}
		if (pointer_args.find(arg_no) != pointer_args.end()) {
			auto *obj = new FunctionArgument(
				curr_arg_val, curr_arg_val->getType(), fi->func, call_sites);
			obj->addPointerPointsTo(curr_arg_val, loc);
			// Record the pto in the global state.
			if (curr_points_to) {
				auto *pto = new PointerPointsTo(curr_arg_val, obj, 0, loc, false);
				if (curr_points_to->find(curr_arg_val) == curr_points_to->end()) {
					(*curr_points_to)[curr_arg_val] = new std::set<PointerPointsTo*>();
				}
				(*curr_points_to)[curr_arg_val]->insert(pto);
			}
			if (tainted_arg_data.find(arg_no) != tainted_arg_data.end()) {
				obj->setAsTaintSrc(loc, false);
			}
		}
		arg_no++;
	}
}

bool AnalysisPass::runOnModule(llvm::Module &m) {
	auto *target_checker = new KernelFunctionChecker();
	auto &range_analysis = getAnalysis<RangeAnalysis::InterProceduralRA<RangeAnalysis::CropDFS>>();
	auto *curr_data_layout = new DataLayout(&m);
	GlobalState curr_state(&range_analysis, curr_data_layout);
	AliasAnalysisVisitor::callback->setPrivateData(&curr_state);
	AliasAnalysisVisitor::callback->targetChecker = target_checker;
	TaintAnalysisVisitor::functionChecker = target_checker;

	auto &dma_analysis = getAnalysis<DMAResult>();
	curr_state.device_info = dma_analysis.getResult();

	// auto *phy_dma_addr = InstructionUtils::stripAllCasts(llvm::dyn_cast<llvm::Value>(&I), true);
	// auto *loc = new InstLoc(phy_dma_addr, this->currFuncCallSites);
	// auto *curr_tag = new TaintTag(0, phy_dma_addr, false);
	// auto *curr_flag = new TaintFlag(loc, true, curr_tag);
	// auto *curr_taint_info = new std::set<TaintFlag*>();
	// curr_taint_info->insert(curr_flag);
	// TaintUtils::updateTaintInfo(this->currState, this->currFuncCallSites, phy_dma_addr, curr_taint_info);

	// for (auto &func: m) {
	// 	for (auto &bb: func) {
	// 		for (auto &inst: bb) {
	// 			llvm::dbgs() << inst << "\n";
	// 			auto debug_loc = inst.getDebugLoc();
	// 			if (!debug_loc) {
	// 				continue;
	// 			}
	// 			// inst.getDebugLoc().dump();
	// 			llvm::dbgs() << "\n";
	// 			llvm::dbgs() << inst.getDebugLoc()->getFilename().str() << "\n";
	// 		}
	// 	}
	// }
	// exit(0);

	// Setup aliases for global variables.
	// setupGlobals(m);

	// hz: taint all global objects, field-sensitive;
	// addGlobalTaintSource(curr_state);
	
	// Get the target functions to be analyzed.
	// getDMAVals(curr_state);
	getTargetFunctions(m);

	goto result;

	for (auto *fi: targetFuncs) {
		if (!fi || !fi->func || fi->func->isDeclaration()) {
			continue;
		}
		auto &func = *(fi->func);
		auto *traversal_order = BBTraversalHelper::getSCCTraversalOrder(func);
		auto *p_call_sites = new std::vector<llvm::Instruction *>();
		p_call_sites->push_back(func.getEntryBlock().getFirstNonPHIOrDbg());

		std::vector<VisitorCallback *> all_callbacks;
		auto *dma_visitor_callback = new DMAAnalysisVisitor(curr_state, &func, p_call_sites);
		all_callbacks.push_back(dma_visitor_callback);

		llvm::dbgs() << "Analyzing function " << func.getName().str() << " in the first stage.\n";
		auto *vis = new GlobalVisitor(curr_state, &func, p_call_sites, traversal_order, all_callbacks);
		DRCHECKER::currEntryFunc = &func;
		vis->analyze();
	}

	// for (auto *fi: targetFuncs) {
	// 	if (!fi || !fi->func || fi->func->isDeclaration()) {
	// 		continue;
	// 	}
	// 	auto &func = *(fi->func);
	// 	auto func_name = func.getName();
	// 	if (!func_name.contains("send_dma_cmd")) {
	// 		continue;
	// 	}
	// 	auto *p_call_sites = new std::vector<llvm::Instruction *>();
	// 	p_call_sites->push_back(func.getEntryBlock().getFirstNonPHIOrDbg());
	// 	setupArgs(fi, curr_state, p_call_sites);
	// }

	for (auto *fi: targetFuncs) {
		if (!fi || !fi->func || fi->func->isDeclaration()) {
			continue;
		}
		auto &func = *(fi->func);
		auto *traversal_order = BBTraversalHelper::getSCCTraversalOrder(func);
		auto *p_call_sites = new std::vector<llvm::Instruction *>();
		p_call_sites->push_back(func.getEntryBlock().getFirstNonPHIOrDbg());
		// setupFunctionArgs(fi, curr_state, p_call_sites);

		auto *path_visitor_callback =
			new PathAnalysisVisitor(curr_state, &func, p_call_sites);
		auto *alias_visitor_callback = 
			new AliasAnalysisVisitor(curr_state, &func, p_call_sites);
		auto *taint_visitor_callback =
			new TaintAnalysisVisitor(curr_state, &func, p_call_sites);
		std::vector<VisitorCallback*> all_callbacks;
		all_callbacks.push_back(alias_visitor_callback);
		all_callbacks.push_back(taint_visitor_callback);
		all_callbacks.push_back(path_visitor_callback);

		llvm::dbgs() << "Analyzing function " << func.getName().str() << " in the second stage.\n";
		auto *vis = new GlobalVisitor(
			curr_state, &func, p_call_sites, traversal_order, all_callbacks);
		DRCHECKER::currEntryFunc = &func;
		vis->analyze();
	}

	curr_state.analysis_phase = 3;
	for (auto *fi: targetFuncs) {
		if (!fi || !fi->func || fi->func->isDeclaration()) {
			continue;
		}
		auto &func = *(fi->func);
		auto *tarversal_order = BBTraversalHelper::getSCCTraversalOrder(func);

		auto *p_call_sites = new std::vector<Instruction *>();
		p_call_sites->push_back(func.getEntryBlock().getFirstNonPHIOrDbg());

		std::vector<VisitorCallback *> all_call_backs;
		VisitorCallback *DMA_detector = 
			new DMADetector(curr_state, &func, p_call_sites, target_checker);
		all_call_backs.push_back(DMA_detector);
		// BugDetectorDriver::addPreAnalysisBugDetectors(
		// 	curr_state, &func, p_call_sites, &all_call_backs, target_checker);
		// BugDetectorDriver::addPostAnalysisBugDetectors(
		// 	curr_state, &func, p_call_sites, &all_call_backs, target_checker);
		llvm::dbgs() << "Analyzing function " << func.getName().str() << " in the third stage.\n";
		auto *vis = new GlobalVisitor(
			curr_state, &func, p_call_sites, tarversal_order, all_call_backs);
		DRCHECKER::currEntryFunc = &func;
		vis->analyze();
	}

	//Output all potential bugs.
//            if(outputFile == "") {
//                // No file provided, write to dbgs()
//                dbgs() << "[+] Writing JSON output :\n";
//                dbgs() << "[+] JSON START:\n\n";
//                BugDetectorDriver::printAllWarnings(curr_state, dbgs());
//                BugDetectorDriver::printWarningsByInstr(curr_state, dbgs());
//                dbgs() << "\n\n[+] JSON END\n";
//            } else {
//                std::error_code res_code;
//                dbgs() << "[+] Writing output to:" << outputFile << "\n";
//                llvm::raw_fd_ostream op_stream(outputFile, res_code, llvm::sys::fs::OF_Text);
//                BugDetectorDriver::printAllWarnings(curr_state, op_stream);
//                op_stream.close();
//
//                dbgs() << "[+] Return message from file write:" << res_code.message() << "\n";
//
//                std::string instrWarningsFile;
//                std::string originalFile = instrWarnings;
//                if(!originalFile.empty()) {
//                    instrWarningsFile = originalFile;
//                } else {
//                    instrWarningsFile = outputFile;
//                    instrWarningsFile.append(".instr_warngs.json");
//                }
//
//                dbgs() << "[+] Writing Instr output to:" << instrWarningsFile << "\n";
//                llvm::raw_fd_ostream instr_op_stream(instrWarningsFile, res_code, llvm::sys::fs::OF_Text);
//                BugDetectorDriver::printWarningsByInstr(curr_state, instr_op_stream);
//                instr_op_stream.close();
//
//                dbgs() << "[+] Return message from file write:" << res_code.message() << "\n";
//            }
//
result:
	curr_state.device_info.dma_insts = curr_state.dma_inst_set;
	auto &dma_taint_result = getAnalysis<DMATaintResult>();
	dma_taint_result.setResult(curr_state.device_info);

	// std::vector<std::tuple<int, int, llvm::Value *>> dma_vals;
	// std::error_code res_code;
	// llvm::raw_fd_ostream op_stream(outputFile, res_code, llvm::sys::fs::OF_Text);
	// llvm::dbgs() << "size: " << curr_state.dma_inst_set.size() << "\n";
	// for (auto &inst: curr_state.dma_inst_set) {
	// 	llvm::dbgs() << *inst << "\n";
	// 	auto &debug_info = inst->getDebugLoc();
	// 	if (!debug_info) {
	// 		continue;
	// 	}
	// 	auto debug_file_name = debug_info->getFilename().str();
	// 	auto file_name = m.getSourceFileName();
	// 	llvm::dbgs() << file_name << " " << debug_file_name << "\n";
	// 	if (file_name.find(debug_file_name) == file_name.npos) {
	// 		continue;
	// 	}
	// 	dma_vals.push_back(std::make_tuple(
	// 		debug_info.getLine(), debug_info->getColumn(), inst));
	// }
	// std::sort(dma_vals.begin(), dma_vals.end());
	// for (auto &val: dma_vals) {
	// 	op_stream << "  - " << std::get<0>(val) << " " << std::get<1>(val) << " " << *std::get<2>(val) << "\n";
	// }
	// op_stream.close();

	return true;
}

void AnalysisPass::getAnalysisUsage(AnalysisUsage &AU) const {
	AU.setPreservesAll();
	AU.addRequired<DMAPass>();
	AU.addRequired<DMAResult>();
	AU.addRequired<DMATaintResult>();

	AU.addRequired<RangeAnalysis::InterProceduralRA<RangeAnalysis::CropDFS>>();
	AU.addRequired<CallGraphWrapperPass>();
	AU.addRequired<LoopInfoWrapperPass>();
}

char AnalysisPass::ID = 0;
static RegisterPass<AnalysisPass> x("truman", "Truman analyzer", false, true);
};
