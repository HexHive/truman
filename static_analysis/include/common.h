#ifndef _COMMON_H_
#define _COMMON_H_

#include <set>
#include <mutex>
#include <iostream>
#include <sstream>

#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Support/NativeFormatting.h"
#include "Graphs/PTACallGraph.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "Util/Options.h"
#include "yaml-cpp/yaml.h"

#include "blacklist.h"

typedef std::map<llvm::Value *, std::set<llvm::Value *>> PointerAnalysisMap;
typedef std::unordered_map<llvm::Function *, PointerAnalysisMap> FuncPointerAnalysisMap;
typedef std::unordered_map<llvm::Function *, llvm::AAResults *> FuncAAResultsMap;
typedef std::string PathInfo;
typedef std::vector<uint64_t> Ops;

namespace DRCHECKER {

enum DEVICE_TYPE {
	k_PCI,
	k_PLATFORM,
};

enum IntraDepNodeType {
	k_NODE_NUM,
	k_NODE_OP,
};

enum IntraDepNodeValueType {
	k_NODE_VALUE_ADD,

    k_NODE_VALUE_AND,
    k_NODE_VALUE_OR,
    k_NODE_VALUE_SHL,
    k_NODE_VALUE_LSHR,

    k_NODE_VALUE_CONSTANT,
    k_NODE_VALUE_CALL,
    k_NODE_VALUE_PHI,
    k_NODE_VALUE_SELECT,
	k_NODE_VALUE_ARG,

	k_NODE_VALUE_COMMON,

    k_NODE_VALUE_NUM_TYPE,
};

class IntraDepNode;
using IntraDepNodePtr = std::shared_ptr<IntraDepNode>;

class IntraDepNode {
public:
    uint64_t value;
	size_t var_cnt;
    IntraDepNodeValueType node_value_type;
    std::vector<IntraDepNodePtr> children; // For operands

    IntraDepNode() {}

    // Constructor for nodes representing operators
    IntraDepNode(IntraDepNodeValueType type)
        : node_value_type(type) {}

    // Constructor for nodes representing constants
    IntraDepNode(IntraDepNodeValueType type, uint64_t val)
        : node_value_type(type), value(val) {}

	// Constructor
    IntraDepNode(uint64_t val, size_t vc, IntraDepNodeValueType nvt)
        : value(val), var_cnt(vc), node_value_type(nvt) {}

    // Additional constructor to initialize with children
    IntraDepNode(uint64_t val, size_t vc, IntraDepNodeValueType nvt, const std::vector<std::shared_ptr<IntraDepNode>>& ch)
        : value(val), var_cnt(vc), node_value_type(nvt), children(ch) {}

	    // Custom copy constructor
    IntraDepNode(const IntraDepNode& other)
        : value(other.value), node_value_type(other.node_value_type),
		var_cnt(other.var_cnt) {
        // Deep copy children
        for (const auto& child : other.children) {
            children.push_back(std::make_unique<IntraDepNode>(*child));
        }
    }

    // Custom move constructor
    IntraDepNode(IntraDepNode&& other) noexcept
        : value(std::move(other.value)),
          node_value_type(std::move(other.node_value_type)),
          children(std::move(other.children)),
		  var_cnt(std::move(other.var_cnt)) {}

    // Custom copy assignment operator
    IntraDepNode& operator=(const IntraDepNode& other) {
        if (this != &other) {
            value = other.value;
            node_value_type = other.node_value_type;
            children.clear();
			var_cnt = other.var_cnt;
            for (const auto& child : other.children) {
                children.push_back(std::make_unique<IntraDepNode>(*child));
            }
        }
        return *this;
    }

    // Custom move assignment operator
    IntraDepNode& operator=(IntraDepNode&& other) noexcept {
        if (this != &other) {
            value = std::move(other.value);
            node_value_type = std::move(other.node_value_type);
            children = std::move(other.children);
			var_cnt = std::move(other.var_cnt);
        }
        return *this;
    }

    // Function to add a child node
    void addChild(IntraDepNodePtr child) {
		if (child) {
			children.push_back(std::move(child));
		}
    }

	void clearChildren() {
        children.clear();
    }

	size_t ChildrenSize() {
		return children.size();
	}

	void replaceRootWithFirstChild() {
        if (children.size() == 1) {
            *this = std::move(*children[0]);
        }
    }

	bool isLeafNode() {
		return children.empty();
	}

	// static bool areTreesEqual(const IntraDepNodePtr& root1, const IntraDepNodePtr& root2) {
	static bool areTreesEqual(const IntraDepNodePtr& root1, const IntraDepNodePtr& root2) {
        if (!root1 && !root2) {
            return true;
        }
        if (!root1 || !root2) {
            return false;
        }
        if (root1->node_value_type != root2->node_value_type || root1->value != root2->value || root1->children.size() != root2->children.size()) {
            return false;
        }
        for (size_t i = 0; i < root1->children.size(); ++i) {
            if (!areTreesEqual(root1->children[i], root2->children[i])) {
                return false;
            }
        }
        return true;
    }

	void printNodeTree(int level = 0) const {
		std::string indent(level * 2, ' '); // 2 spaces per level

		if (!children.empty()) {
			for (size_t i = 0; i < children.size(); ++i) {
				if (i == 0) {
					llvm::dbgs() << indent << valueAsString() << "\n";
				}
				children[i]->printNodeTree(level + 1);
			}
		} else {
			llvm::dbgs() << indent << valueAsString() << "\n";
		}
	}

	void printNode(int level = 0) const {
        if (!children.empty()) {
			llvm::dbgs() << "(";
            for (size_t i = 0; i < children.size(); ++i) {
                children[i]->printNode(level + 1);
                if (i < children.size() - 1) {
					llvm::dbgs() << " " << valueAsString() << " ";
                }
            }
			llvm::dbgs() << ")";
        } else {
			llvm::dbgs() << valueAsString();
        }
		llvm::dbgs() << "\n";
    }

    // Convert node value type to string
    std::string valueAsString() const {
		std::stringstream ss;
        switch (node_value_type) {
            case IntraDepNodeValueType::k_NODE_VALUE_ADD:
                return "ADD#" + std::to_string(var_cnt);
            case IntraDepNodeValueType::k_NODE_VALUE_AND:
                return "AND#" + std::to_string(var_cnt);
            case IntraDepNodeValueType::k_NODE_VALUE_OR:
                return "OR#" + std::to_string(var_cnt);
            case IntraDepNodeValueType::k_NODE_VALUE_SHL:
                return "SHL#" + std::to_string(var_cnt);
            case IntraDepNodeValueType::k_NODE_VALUE_LSHR:
                return "LSHR#" + std::to_string(var_cnt);
            case IntraDepNodeValueType::k_NODE_VALUE_CONSTANT:
				ss << std::hex << "0x" << value << "#0";
				return ss.str();
            case IntraDepNodeValueType::k_NODE_VALUE_CALL:
                return "CALL#" + std::to_string(var_cnt) + "#" + std::to_string(value);
			case IntraDepNodeValueType::k_NODE_VALUE_PHI:
				return "PHI#" + std::to_string(var_cnt);
			case IntraDepNodeValueType::k_NODE_VALUE_SELECT:
				return "SELECT#" + std::to_string(var_cnt);
			case IntraDepNodeValueType::k_NODE_VALUE_ARG:
				return "ARG#" + std::to_string(var_cnt);
			case IntraDepNodeValueType::k_NODE_VALUE_COMMON:
				return "COMMON#" + std::to_string(var_cnt);
            default:
                return "UNKNOWN#" + std::to_string(var_cnt);
        }
    }

	friend YAML::Emitter& operator<<(YAML::Emitter& out, const IntraDepNode& node) {
		// if (!node.children.empty()) {
		// 	out << YAML::Flow;
		// 	out << YAML::BeginSeq;
		// 	for (size_t i = 0; i < node.children.size(); ++i) {
		// 		out << *node.children[i];
		// 		if (i < node.children.size() - 1) {
		// 			out << node.valueAsString();
		// 		}
		// 	}
		// 	out << YAML::EndSeq;
		// } else {
		// 	out << node.valueAsString();
		// }
		out << YAML::BeginMap;
        out << YAML::Key << "Operator" << YAML::Value << node.valueAsString();
        if (!node.children.empty()) {
            out << YAML::Key << "Children" << YAML::Value << YAML::BeginSeq;
            for (const auto& child : node.children) {
                out << *child;
            }
            out << YAML::EndSeq;
        }
        out << YAML::EndMap;

		return out;
	}

};

struct Operation {
    llvm::CallInst *call_inst;
	llvm::DILocation *debug_loc;
    uint64_t id;
    std::string op_type;
    std::string op_rw;
    uint64_t region_id;
    std::string name;
    ssize_t size;
    std::set<uint64_t> reg;
    IntraDepNodePtr reg_node;

    Operation() : call_inst(nullptr), debug_loc(nullptr), id(0), region_id(0), size(0) {}

	Operation(const Operation& other)
        : call_inst(other.call_inst), debug_loc(other.debug_loc), id(other.id), op_type(other.op_type),
          op_rw(other.op_rw), region_id(other.region_id), name(other.name),
          size(other.size), reg(other.reg) {
        // Deep copy reg_node
        if (other.reg_node) {
            reg_node = std::make_unique<IntraDepNode>(*other.reg_node);
        }
    }

    // Custom move constructor
    Operation(Operation&& other) noexcept
        : call_inst(std::move(other.call_inst)), debug_loc(std::move(other.debug_loc)), id(std::move(other.id)),
          op_type(std::move(other.op_type)), op_rw(std::move(other.op_rw)),
          region_id(std::move(other.region_id)), name(std::move(other.name)),
          size(std::move(other.size)), reg(std::move(other.reg)),
          reg_node(std::move(other.reg_node)) {}

    // Custom copy assignment operator
    Operation& operator=(const Operation& other) {
        if (this != &other) {
            call_inst = other.call_inst;
			debug_loc = other.debug_loc;
            id = other.id;
            op_type = other.op_type;
            op_rw = other.op_rw;
            region_id = other.region_id;
            name = other.name;
            size = other.size;
            reg = other.reg;
            // Deep copy reg_node
            if (other.reg_node) {
                reg_node = std::make_unique<IntraDepNode>(*other.reg_node);
            } else {
                reg_node.reset();
            }
        }
        return *this;
    }

    // Custom move assignment operator
    Operation& operator=(Operation&& other) noexcept {
        if (this != &other) {
            call_inst = std::move(other.call_inst);
			debug_loc = std::move(other.debug_loc);
            id = std::move(other.id);
            op_type = std::move(other.op_type);
            op_rw = std::move(other.op_rw);
            region_id = std::move(other.region_id);
            name = std::move(other.name);
            size = std::move(other.size);
            reg = std::move(other.reg);
            reg_node = std::move(other.reg_node);
        }
        return *this;
    }
};

struct CalleeOrOp {
    bool duplicate;
    uint64_t id;
    enum { IsCallee, IsOperation } kind;
    union {
        llvm::Function* callee;
        Operation operation;
    };

    // Default constructor
    CalleeOrOp() : duplicate(false), id(0), kind(IsOperation), operation() {}

    // Destructor
    ~CalleeOrOp() {
        if (kind == IsOperation) {
            operation.~Operation();
        }
    }

    // Copy constructor
    CalleeOrOp(const CalleeOrOp& other) : duplicate(other.duplicate), id(other.id), kind(other.kind) {
        if (kind == IsOperation) {
            new (&operation) Operation(other.operation);
        } else {
            callee = other.callee;
        }
    }

    // Copy assignment operator
    CalleeOrOp& operator=(const CalleeOrOp& other) {
        if (this != &other) {
            if (kind == IsOperation) {
                operation.~Operation();
            }
            duplicate = other.duplicate;
            id = other.id;
            kind = other.kind;
            if (kind == IsOperation) {
                new (&operation) Operation(other.operation);
            } else {
                callee = other.callee;
            }
        }
        return *this;
    }
};

struct FunctionInfo {
	llvm::Function *func;
	std::set<PathInfo> paths;
};

enum EleType {
	k_STRUCT_,
	k_ARRAY_,
	k_INT_,
	k_POINTER_,
};

struct DMAType {
	EleType ele_type;
	std::string name;
	uint64_t num;
	uint64_t width;
	std::vector<struct DMAType *> dma_type;
};

enum DMA_TYPE {
	k_COHERENT,
	k_STREAMING,
};

struct DMAInfo {
	uint64_t id;
	std::set<llvm::Value *> phy_addr;
	std::set<llvm::Value *> virt_addr;
	std::set<uint64_t> phy_bytes;
	std::set<uint64_t> virt_bytes;
	std::pair<uint64_t, uint64_t> debug_loc;
	struct DMAType *structure;
	llvm::Type *dma_type;
	enum DMA_TYPE type;
	llvm::Instruction *inst;
};

struct IOInfo {
	uint64_t region_id;
	bool is_mmio;
	std::string device_type;
	std::vector<uint64_t> offset;
	std::set<uint64_t> bytes;
	std::set<const llvm::Value *> var;
};

struct DeviceInfo {
	std::string device_name;
	std::string bc_path;
	llvm::Module *bc_module;
	llvm::Module *bc_module_O0;
	llvm::LLVMContext *llvm_context;
	const llvm::DataLayout *data_layout;

	SVF::LLVMModuleSet *svf_module_set;
	SVF::SVFModule *svf_module;
	SVF::SVFIR *svf_pag;
	SVF::Andersen *svf_ander;
	SVF::PTACallGraph *svf_cg;
	SVF::ICFG *svf_icfg;
	SVF::VFG *svf_vfg;
	SVF::SVFG *svf_svfg;

	FuncPointerAnalysisMap func_pa_results;
	FuncAAResultsMap func_aar_results;
	
	DEVICE_TYPE device_type;
	std::set<llvm::Function *> probe_func;
	llvm::Function *int_func;
	std::vector<FunctionInfo> func_infos;
	std::set<llvm::Function *> visited_funcs;
	std::set<llvm::Function *> entries;
	std::set<llvm::Function *> funcs;
	std::vector<struct IOInfo> io_info;
	std::map<const llvm::BasicBlock *, Ops> bb_ops_map;
	std::map<const llvm::BasicBlock *, std::set<PathInfo>> bb_path_map;
	std::map<const llvm::BasicBlock *, uint64_t> bb_num_map;
	std::set<const llvm::BasicBlock *> visited_bbs;
	std::set<const llvm::Value*> visited_reg_values;
	std::stack<const llvm::BasicBlock *> bbs_stack;
	std::set<const SVF::VFGNode *> visited_nodes;
	std::vector<CalleeOrOp> ops;
	uint64_t unique_ops;
	uint64_t io_region_num;
	uint64_t bb_num;
	uint64_t path_num;
	std::map<llvm::Value*, IntraDepNodePtr> val2node_map;
	uint64_t intra_num;

	std::vector<struct DMAInfo> dma_info;
	std::set<std::tuple<int, int>> dma_vals;
	std::set<llvm::Instruction *> dma_insts;
	uint64_t dma_num;
	std::set<uint64_t> nested_dma;

	std::set<llvm::Function *> state_func;

	// Default constructor
    DeviceInfo()
        : device_name(""), bc_path(""), bc_module(nullptr), bc_module_O0(nullptr),
          llvm_context(nullptr), data_layout(nullptr), svf_module_set(nullptr),
          svf_module(nullptr), svf_pag(nullptr), svf_ander(nullptr), svf_cg(nullptr),
          svf_icfg(nullptr), svf_vfg(nullptr), svf_svfg(nullptr), int_func(nullptr),
          device_type(DEVICE_TYPE()), unique_ops(0), io_region_num(0), bb_num(0),
          path_num(0), dma_num(0), intra_num(0) {}
};

struct GlobalContext {
	std::mutex global_context_mutex;

	std::shared_ptr<spdlog::logger> logger;

	std::vector<DeviceInfo> devices;
};

enum OP_TYPE {
	k_IO,
	k_MMIO,
	k_CONFIG,
	k_FUNC_TYPE_NUM,
};

enum RW {
	k_READ,
	k_WRITE,
};

typedef std::tuple<std::string, uint8_t, DMA_TYPE> DMAFunc;
typedef std::tuple<std::string, std::string> Func2Type;
typedef std::tuple<std::string, OP_TYPE, uint8_t, uint64_t, RW, uint8_t, uint8_t, uint8_t> WriteFunc;
typedef std::tuple<std::string, uint64_t> DeviceIOAddr;
typedef std::tuple<std::string, uint8_t> RegionNameID;
}

using namespace DRCHECKER;

#endif // _COMMON_H_
