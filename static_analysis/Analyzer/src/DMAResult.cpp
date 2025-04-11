#include "DMAResult.h"

char DMAResult::ID = 0;
static llvm::RegisterPass<DMAResult> X("dma-result", "DMA Result Pass", false, true);

char DMATaintResult::ID = 0;
static llvm::RegisterPass<DMATaintResult> Y("dma-taint-result", "DMA Taint Result Pass", false, true);