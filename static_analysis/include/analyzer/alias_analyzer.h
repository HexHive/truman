#ifndef _ALIAS_ANALYZER_H_
#define _ALIAS_ANALYZER_H_

#include "analyzer/analyzer.h"

class AliasAnalyzer: public Analyzer {
public:
	AliasAnalyzer(DeviceInfo&, std::shared_ptr<spdlog::logger>);
	~AliasAnalyzer() {};

	virtual void Analyze() override;
private:
	void DetectAliasPointers(llvm::Function *, llvm::AAResults &, PointerAnalysisMap &);
	llvm::Value *GetSourcePointer(llvm::Value *);
};

#endif
