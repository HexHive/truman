#include "common.h"

#include "llvm/Pass.h"

using dma_info = std::vector<struct DMAInfo>;

class DMAResult: public llvm::ImmutablePass {
public:
	static char ID;
	DMAResult(): llvm::ImmutablePass(ID) {}

	void setResult(DeviceInfo res) {
		result = res;
	}

	DeviceInfo getResult() const {
		return result;
	}

private:
	DeviceInfo result;
};

using dma_taint_result = std::set<llvm::Instruction *>;

class DMATaintResult: public llvm::ImmutablePass {
public:
	static char ID;
	DMATaintResult(): llvm::ImmutablePass(ID) {}

	void setResult(DeviceInfo res) {
		result = res;
	}
	DeviceInfo getResult() const {
		return result;
	}

private:
	DeviceInfo result;
};