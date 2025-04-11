#ifndef _IO_ANALYZER_H_
#define _IO_ANALYZER_H_

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"

#include "analyzer/analyzer.h"

class IOAnalyzer: public Analyzer {
public:
	IOAnalyzer(DeviceInfo&, std::shared_ptr<spdlog::logger>);
	~IOAnalyzer() {};

	virtual void Analyze() override;
private:
	const std::vector<WriteFunc> default_rw_funcs = {
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
		// std::make_tuple("__ew32",	 		k_MMIO,	4, 		   0xFFFFFFFF,	k_WRITE, 0, 1, 2), // e1000e

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
		std::make_tuple("vga_r",	 		k_MMIO,	1, 			     0xFF,	k_READ, 0, 1, -1),

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
	const std::vector<DMAFunc> default_dma_funcs = {
		std::make_tuple("dma_alloc_attrs",		2,	k_COHERENT),
		std::make_tuple("dma_alloc_coherent",	2,	k_COHERENT),
		std::make_tuple("dma_map_single",		-1,	k_STREAMING),
		std::make_tuple("dma_map_page",			-1,	k_STREAMING),
		std::make_tuple("dma_map_resource",		-1,	k_STREAMING),
	};
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

	llvm::Function *FindPCIProbe(llvm::Module *);
	llvm::ConstantStruct *FindDriver(llvm::Module *);

	bool AnalyzeIOBar(llvm::Function *);
	bool AnalyzeDMA(llvm::Function *, bool opt=false);
	void AnalyzeFunc(llvm::Function *);
	bool AnalyzeProbe();
	bool AnalyzeResource();
	bool AnalyzeEntries(bool opt=false);
	bool AnalyzeEntries(llvm::GlobalVariable *, bool opt=false);
	bool AnalyzeBB(llvm::BasicBlock *);
	bool AnalyzePath(llvm::Function *);
	bool AnalyzeDMAAccess(llvm::Function *);
	std::set<PathInfo> AnalyzePath(llvm::BasicBlock *, std::set<llvm::BasicBlock *> &);
	struct CalleeOrOp AnalyzeCall(llvm::CallInst *);

	uint64_t GetValue(llvm::Value *);
	uint64_t IsDMA(llvm::Instruction *);
	std::set<uint64_t> GetReg(llvm::Value *, uint64_t &, bool);
	bool GetIOInfo(const llvm::Value *, std::set<uint64_t> &);
	const llvm::Value *GetOffset(llvm::Value *, std::set<uint64_t> &, bool);
	std::set<llvm::Value *> GetStoredReturnVal(llvm::Value *);
	bool GetBytes(const SVF::VFGNode *, uint64_t, std::set<uint64_t> &);
	void GetAliasPointers(llvm::Value *, std::set<llvm::Value *> &, PointerAnalysisMap &);
	void GetDebugLoc(llvm::Instruction *, std::pair<uint64_t, uint64_t> &, bool enable_inline=true);
	struct DMAType *GetDMAType(llvm::Type *);
	llvm::Value *GetSourcePointer(llvm::Value *);

	const llvm::Value* FindSource(const llvm::Value *, std::stack<const SVF::VFGNode *> &);
	uint64_t MatchIO(const llvm::Value *, struct IOInfo &);
	uint64_t MatchIOVar(const llvm::Value *);

	bool ExtractInt(const llvm::GetElementPtrInst *, std::vector<uint64_t> &);
	uint64_t CalOffset(const llvm::GetElementPtrInst *);
	std::string Type2Str(llvm::Type *);
	uint64_t FindOp(CalleeOrOp);

	void ProcessProbe(llvm::Function *);
};

#endif
