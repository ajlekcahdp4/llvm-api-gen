#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Support/raw_ostream.h>

namespace lag {
using namespace llvm;
class api_gen_pass : public PassInfoMixin<api_gen_pass> {
  raw_ostream &os;

public:
  api_gen_pass(raw_ostream &os) : os(os) {}
  PreservedAnalyses run(Module &m, ModuleAnalysisManager &);
};
} // namespace lag
