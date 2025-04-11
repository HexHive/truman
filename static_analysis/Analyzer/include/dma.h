#ifndef _DMA_H_
#define _DMA_H_

#include "common.h"
#include "DMAResult.h"

class DMAPass : public llvm::ModulePass {
public:
	static char ID;
	DMAPass(): llvm::ModulePass(ID) {
		device_info_ = {};
	}

	using Result = DeviceInfo;
	Result device_info_;
	llvm::Module *module_;

	const std::vector<DMAFunc> default_dma_funcs = {
		std::make_tuple("dma_alloc_attrs",			2,	k_COHERENT),
		std::make_tuple("dma_alloc_coherent",		2,	k_COHERENT),
		std::make_tuple("dmam_alloc_attrs",			2,	k_COHERENT),
		std::make_tuple("dmam_alloc_coherent",		2,	k_COHERENT),
		std::make_tuple("dma_map_single",			-1,	k_STREAMING),
		std::make_tuple("dma_map_page",				-1,	k_STREAMING),
		std::make_tuple("dma_map_resource",			-1,	k_STREAMING),
		std::make_tuple("dma_mmap_pages",			-1, k_STREAMING),
		std::make_tuple("dma_alloc_pages",			-1, k_STREAMING),
		std::make_tuple("dma_alloc_noncoherent",	-1, k_STREAMING),
		std::make_tuple("dma_alloc_noncontiguous",	-1, k_STREAMING),
		std::make_tuple("snd_devm_alloc_dir_pages",	-1, k_STREAMING),
	};
	const std::vector<std::string> default_ops = {
		"struct.watchdog_ops",
		"struct.ethtool_ops",
		"struct.net_device_ops",
		"struct.dev_pm_ops",
		"struct.fb_ops",
		"struct.drm_simple_display_pipe_funcs",
		"struct.hc_driver",
	};

	llvm::Type* GV2Type(llvm::GlobalVariable *global_variable);

	llvm::ConstantStruct *FindDriver(llvm::Module *module);
	llvm::Function *FindPCIProbe(llvm::Module *M);

	bool AnalyzeResource(llvm::Module *M);
	bool AnalyzeEntries();
	bool AnalyzeEntries(llvm::GlobalVariable *global);
	bool AnalyzeDMA(llvm::Function *func);
	bool AnalyzeDMAAccess(llvm::Function *func);

	llvm::Value *GetSourcePointer(llvm::Value *val);
	void GetDebugLoc(llvm::Instruction *inst,
		std::pair<uint64_t, uint64_t> &debug_loc, bool enable_inline);
	bool GetIOInfo(const llvm::Value *val, std::set<uint64_t> &bytes);
	bool GetBytes(const SVF::VFGNode *vfg_node, uint64_t offset,
		std::set<uint64_t> &reg);
	uint64_t CalOffset(const llvm::GetElementPtrInst *gep_inst);
	std::set<llvm::Value*> GetStoredReturnVal(llvm::Value *val);
	void GetAliasPointers(llvm::Value *val, std::set<llvm::Value *> &alias_set, PointerAnalysisMap &alias_ptrs);
	void PreProcess();
	void CleanUp();
	void DetectAliasPointers(llvm::Function *func, llvm::AAResults &AAR, PointerAnalysisMap &alias_ptrs);

	// bool run(llvm::Module &M, llvm::ModuleAnalysisManager &);
	bool runOnModule(llvm::Module &M) override;
	void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
};

#endif
