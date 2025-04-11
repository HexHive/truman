#ifndef _DMA_ANALYSIS_H_
#define _DMA_ANALYSIS_H_

#include "dma.h"
#include "common.h"
#include "analysis.h"

#include "llvm/IR/InlineAsm.h"

#include "device.pb.h"
using namespace device;

namespace DRCHECKER {

class DMAAnalysisPass : public llvm::ModulePass {
public:
	static char ID;
	DMAAnalysisPass(): llvm::ModulePass(ID) {
		device_info_ = {};
		dma_result_ = {};
	}

	DeviceInfo device_info_;
	dma_taint_result dma_result_;
	Module *module_;

	bool runOnModule(llvm::Module &M) override;
	void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

	llvm::Value *C2C(uint64_t);
	bool hasOneVariableIndex(llvm::GetElementPtrInst *GEP);
	void AnalyzeNestedDMA();
	void Analyze();
	llvm::Value *GetSourcePointer(llvm::Value *val);
	bool AnalyzeDMAAccess(llvm::Function *func);
	bool AnalyzeResource();
	bool AnalyzeProbe();
	bool AnalyzeDMA(llvm::Function *func);
	struct DMAType *GetDMAType(llvm::Type *type);
	void GetDebugLoc(llvm::Instruction *inst, std::pair<uint64_t, uint64_t> &debug_loc, bool enable_inline);
	bool AnalyzeIOBar(llvm::Function *func);
	bool GetBytes(const SVF::VFGNode *vfg_node, uint64_t offset, std::set<uint64_t> &reg);
	bool GetIOInfo(const llvm::Value *val, std::set<uint64_t> &bytes);
	std::set<llvm::Value*> GetStoredReturnVal(llvm::Value *val);
	bool AnalyzeEntries(llvm::GlobalVariable *global);
	bool AnalyzeEntries();
	struct CalleeOrOp AnalyzeCall(llvm::CallInst *call_inst);
	uint64_t FindOpOrCallee(const CalleeOrOp& op);
	bool AnalyzeBB(llvm::BasicBlock *bb);
	std::set<PathInfo> AnalyzePath(llvm::BasicBlock *bb, std::set<llvm::BasicBlock *> &bb_set);
	bool AnalyzePath(llvm::Function *func);
	void AnalyzeFunc(llvm::Function *func);
	llvm::Function* FindPCIProbe();
	llvm::ConstantStruct *FindDriver();
	uint64_t IsDMA(llvm::Instruction *inst);
	uint64_t GetValue(llvm::Value *value);
	uint64_t MatchIO(const llvm::Value *val, struct IOInfo &target_io_info);
	const llvm::Value* GetOffset(llvm::Value *val, std::set<uint64_t> &reg, bool is_io);
	uint64_t MatchIOVar(const llvm::Value *val);
	std::set<uint64_t> GetReg(llvm::Value *value, uint64_t &region_id, bool is_io);
	uint64_t CalOffset(const llvm::GetElementPtrInst *gep_inst);
	std::string Type2Str(llvm::Type *type);
	bool ExtractInt(const llvm::GetElementPtrInst *gep_inst, std::vector<uint64_t> &offset);
	const llvm::Value* FindSource(const llvm::Value *val, std::stack<const SVF::VFGNode *> &vfg_stack);
	void GetAliasPointers(llvm::Value *val, std::set<llvm::Value *> &alias_set, PointerAnalysisMap &alias_ptrs);
	llvm::Type* GV2Type(llvm::GlobalVariable *global_variable);
	void PreProcess();
	void WriteResult();
	void CleanUp();
	uint64_t FindOpid(const llvm::Instruction *);
	IntraDepNodePtr GetRegValue(llvm::Value *);

	
    void serializeDeviceInfo(const DeviceInfo& device_info, Device* protoDevice);

    // Methods to serialize individual components
    void serializeOperation(const Operation& op, device::Operation* protoOp);
	void serializeCallee(llvm::Function* callee, device::Callee* protoCallee);
	void serializeCalleeOrOp(const CalleeOrOp& calleeOrOp, device::CalleeOrOp* protoCalleeOrOp);

    void serializeIntraDepNode(const IntraDepNodePtr& node, device::IntraDepNode* protoNode);
    void serializeIO(const IOInfo& io, device::IO* protoIO);
	void serializeBasicBlocks(const DeviceInfo& device_info, google::protobuf::Map<std::string, std::string>* protoBBs);
	void serializeFuncs(const std::vector<FunctionInfo>& func_infos, google::protobuf::Map<std::string, device::Function>* protoFuncs);

    // Methods to write serialized data to files
    void writeBinaryToFile(const std::string& filename, const Device& protoDevice);
    void writeTextToFile(const std::string& filename, const Device& protoDevice);
    void writeJsonToFile(const std::string& filename, const Device& protoDevice);

	void printAliasPoints();

	void writeToFile(const std::string& filename, const std::string& data);

	const std::vector<WriteFunc> default_rw_funcs = {
	//					name,				type,	size & mask,			RW, reg, offset, val
		std::make_tuple("iowrite64", 		k_MMIO,	8, 0xFFFFFFFFFFFFFFFF,	k_WRITE, -1, 1, 0), // iowrite, iowritebe, iowrite_rep
		std::make_tuple("iowrite32_rep", 	k_MMIO,	4,		   0xFFFFFFFF,	k_WRITE, -1, 0, 1),
		std::make_tuple("iowrite16_rep", 	k_MMIO,	2, 			   0xFFFF,	k_WRITE, -1, 0, 1),
		std::make_tuple("iowrite8_rep",  	k_MMIO,	1, 			     0xFF,	k_WRITE, -1, 0, 1),
		std::make_tuple("iowrite32", 		k_MMIO,	4,		   0xFFFFFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("iowrite16", 		k_MMIO,	2, 			   0xFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("iowrite8",  		k_MMIO,	1, 			     0xFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("writeq",	 		k_MMIO,	8, 0xFFFFFFFFFFFFFFFF,	k_WRITE, -1, 1, 0), // wirte, write_relaxed, __raw_write, writes
		std::make_tuple("writel",	 		k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("writew",	 		k_MMIO,	2, 			   0xFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("writeb",	 		k_MMIO,	1, 			     0xFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("vga_w",	 		k_MMIO,	1, 			     0xFF,	k_WRITE, 0, 1, 2), // cirrus
		std::make_tuple("vga_w_fast",		k_MMIO,	2, 			   0xFFFF,	k_WRITE, 0, 1, 2), // cirrus
		std::make_tuple("__ew32",	 		k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, 0, 1, 2), // e1000e
		std::make_tuple("igb_wr32",	 		k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, 0, 1, 2), // igb
		std::make_tuple("_aty_st_le32",	 	k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, 2, 0, 1), // ati
		std::make_tuple("_aty_st_8",	 	k_MMIO,	1, 		   		 0xFF,	k_WRITE, 2, 0, 1), // ati
		std::make_tuple("vp_iowrite8",	 	k_MMIO,	1, 		   		 0xFF,	k_WRITE, 1, 1, 0), // virtio
		std::make_tuple("vp_iowrite16",	 	k_MMIO,	2, 		   	   0xFFFF,	k_WRITE, 1, 1, 0), // virtio
		std::make_tuple("vp_iowrite32",	 	k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, 1, 1, 0), // virtio
		std::make_tuple("vp_iowrite64_twopart",	k_MMIO,	8, 0xFFFFFFFFFFFFFFFF,	k_WRITE, 1, 1, 0), // virtio
		std::make_tuple("snd_hdac_reg_writeb",	k_MMIO,	1, 		   	0xFF,	k_WRITE, -1, 1, 2), // intel-hda
		std::make_tuple("snd_hdac_reg_writew",	k_MMIO,	2, 		   	0xFFFF,	k_WRITE, -1, 1, 2), // intel-hda
		std::make_tuple("pvscsi_reg_write",	k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, 0, 1, 2), // pvscsi
		std::make_tuple("vmw_write",		k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, 0, 1, 2), // vmw_write

		std::make_tuple("ioread64",  		k_MMIO,	8, 0xFFFFFFFFFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("ioread32_rep",		k_MMIO,	4, 		   0xFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("ioread16_rep", 	k_MMIO,	2, 			   0xFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("ioread8_rep",  	k_MMIO,	1, 			     0xFF,	k_READ, -1, 0, -1),
		std::make_tuple("ioread32",  		k_MMIO,	4, 		   0xFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("ioread16",  		k_MMIO,	2, 			   0xFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("ioread8",   		k_MMIO,	1, 			     0xFF,	k_READ, -1, 0, -1),
		std::make_tuple("readq",	 		k_MMIO,	8, 0xFFFFFFFFFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("readl",	 		k_MMIO,	4, 		   0xFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("readw",	 		k_MMIO,	2, 			   0xFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("readb",	 		k_MMIO,	1, 			     0xFF,	k_READ, -1, 0, -1),
		std::make_tuple("vga_r",	 		k_MMIO,	1, 			     0xFF,	k_READ,  0, 1, -1),
		std::make_tuple("__er32",	 		k_MMIO,	4, 		   0xFFFFFFFF,	k_READ,  0, 1, -1), // e1000e
		std::make_tuple("igb_rd32",	 		k_MMIO,	4, 		   0xFFFFFFFF,	k_READ,  0, 1, -1), // igb
		std::make_tuple("_aty_ld_le32",	 	k_MMIO,	4, 		   0xFFFFFFFF,	k_READ,  1, 0, -1), // ati
		std::make_tuple("vp_ioread8",	 	k_MMIO,	1, 		   		 0xFF,	k_READ,  1, 1, -1), // virtio
		std::make_tuple("vp_ioread16",	 	k_MMIO,	2, 		   	   0xFFFF,	k_READ,  1, 1, -1), // virtio
		std::make_tuple("vp_ioread32",	 	k_MMIO,	4, 		   0xFFFFFFFF,	k_READ,  1, 1, -1), // virtio
		std::make_tuple("snd_hdac_reg_readb",	k_MMIO,	1, 		   	0xFF,	k_READ, -1, 1, -1), // intel-hda
		std::make_tuple("snd_hdac_reg_readw",	k_MMIO,	2, 		   	0xFFFF,	k_READ, -1, 1, -1), // intel-hda
		std::make_tuple("pvscsi_reg_read",	k_MMIO,	4, 		   0xFFFFFFFF,	k_READ,  0, 1, -1), // pvscsi
		std::make_tuple("vmw_read",			k_MMIO,	4, 		   0xFFFFFFFF,	k_READ,  0, 1, -1), // vmw_write

		std::make_tuple("outl",	 	 		k_IO,	4, 		   0xFFFFFFFF,	k_WRITE, -1, 1, 0), // out, out_p, outs
		std::make_tuple("outw",	 	 		k_IO,	2, 			   0xFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("outb",	 	 		k_IO,	1, 			     0xFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("e1000_io_write",	k_IO,	4, 		   0xFFFFFFFF,	k_WRITE, -1, 1, 2), // e1000

		std::make_tuple("inl",	 	 		k_IO,	4, 		   0xFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("inw",	 	 		k_IO,	2, 			   0xFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("inb",	 	 		k_IO,	1, 			     0xFF,	k_READ, -1, 0, -1),

		std::make_tuple("pci_write_config_dword",	k_CONFIG,	4, 	0xFFFFFFFF,	k_WRITE, -1, 1, 2),
		std::make_tuple("pci_write_config_word",	k_CONFIG,	2, 		0xFFFF,	k_WRITE, -1, 1, 2),
		std::make_tuple("pci_write_config_byte",	k_CONFIG,	1, 		  0xFF,	k_WRITE, -1, 1, 2),
		std::make_tuple("pcie_write_config_dword",	k_CONFIG,	4, 	0xFFFFFFFF,	k_WRITE, -1, 1, 2),
		std::make_tuple("pcie_write_config_word",	k_CONFIG,	2, 		0xFFFF,	k_WRITE, -1, 1, 2),
		std::make_tuple("pci_read_config_dword",	k_CONFIG,	4, 	0xFFFFFFFF,	k_READ, -1, 1, -1),
		std::make_tuple("pci_read_config_word",		k_CONFIG,	2, 		0xFFFF,	k_READ, -1, 1, -1),
		std::make_tuple("pci_read_config_byte",		k_CONFIG,	1, 		  0xFF,	k_READ, -1, 1, -1),
		std::make_tuple("pcie_read_config_dword",	k_CONFIG,	4, 	0xFFFFFFFF,	k_READ, -1, 1, -1),
		std::make_tuple("pcie_read_config_word",	k_CONFIG,	2, 		0xFFFF,	k_READ, -1, 1, -1),
	};
	const std::vector<WriteFunc> default_asm_funcs = {
		std::make_tuple("movq $0,$1",			k_MMIO,	8,	0xFFFFFFFFFFFFFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("movl $0,$1",			k_MMIO,	4,			0xFFFFFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("movw $0,$1",			k_MMIO,	2,				0xFFFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("movb $0,$1",			k_MMIO,	1,				  0xFF,	k_WRITE, -1, 1, 0),
		std::make_tuple("outl $0, ${1:w}",		k_IO,	4,			0xFFFFFFFF, k_WRITE, -1, 1, 0),
		std::make_tuple("outw ${0:w}, ${1:w}",	k_IO,	2,				0xFFFF, k_WRITE, -1, 1, 0),
		std::make_tuple("outb ${0:b}, ${1:w}",	k_IO,	1,				  0xFF, k_WRITE, -1, 1, 0),

		std::make_tuple("movq $1,$0",			k_MMIO,	8,	0xFFFFFFFFFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("movl $1,$0",			k_MMIO,	4,			0xFFFFFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("movw $1,$0",			k_MMIO,	2,				0xFFFF,	k_READ, -1, 0, -1),
		std::make_tuple("movb $1,$0",			k_MMIO,	1,				  0xFF,	k_READ, -1, 0, -1),
		std::make_tuple("inl ${1:w}, $0", 		k_IO,	4,			0xFFFFFFFF, k_READ, -1, 0, -1),
		std::make_tuple("inw ${1:w}, ${0:w}", 	k_IO,	2,				0xFFFF, k_READ, -1, 0, -1),
		std::make_tuple("inb ${1:w}, ${0:b}", 	k_IO,	1,				  0xFF, k_READ, -1, 0, -1),
	};

	const std::vector<RegionNameID> default_region_name_id = {
		std::make_tuple("cap_regs", 1),
		std::make_tuple("op_regs", 2),
		std::make_tuple("run_regs", 11),
	};

	// const std::vector<DMAFunc> default_dma_funcs = {
	// 	std::make_tuple("dma_alloc_attrs",		2,	k_COHERENT),
	// 	std::make_tuple("dmam_alloc_attrs",		2,	k_COHERENT),
	// 	std::make_tuple("dma_alloc_coherent",	2,	k_COHERENT),
	// 	std::make_tuple("dmam_alloc_coherent",	2,	k_COHERENT),
	// 	std::make_tuple("dma_map_single",		-1,	k_STREAMING),
	// 	std::make_tuple("dma_map_page",			-1,	k_STREAMING),
	// 	std::make_tuple("dma_map_resource",		-1,	k_STREAMING),
	// };
	const std::vector<std::string> mmio_mapping_funcs = {
		"ioremap",
		"ioremap_np",
		"ioremap_uc",
		"ioremap_wc",
		"ioremap_wt",
		"ioremap_cache",
		"devm_ioport_map",
		"devm_ioremap",
		"devm_ioremap_uc",
		"devm_ioremap_wc",
		"devm_ioremap_resource",
		"devm_platform_ioremap_resource",
		"devm_ioremap_resource_wc",
		"of_address_to_resource",
		"of_iomap",
		"pci_ioremap_bar",
		"pci_ioremap_wc_bar",
		"pci_iomap",
		"pci_iomap_wc",
		"pcim_iomap",
		"pcim_iomap_table",
		"vp_modern_map_capability",
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
	enum IOResult {
		kmatch,
		kvar_not_match,
		koffset_not_match,
		knot_match,
	};
};
}

#endif
