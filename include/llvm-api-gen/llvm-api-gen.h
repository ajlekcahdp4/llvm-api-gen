#pragma once

#include <llvm/IR/PassManager.h>

namespace lag {
using namespace llvm;
class api_gen_pass : public PassInfoMixin<api_gen_pass> {
public:
  PreservedAnalyses run(Function &f, FunctionAnalysisManager &);
};
} // namespace lag
