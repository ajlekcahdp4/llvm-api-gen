#include "llvm-api-gen/llvm-api-gen.h"

#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

namespace lag {

PreservedAnalyses api_gen_pass::run(Function &f, FunctionAnalysisManager &) {
  f.dump();
  return PreservedAnalyses::all();
}

} // namespace lag

using namespace llvm;
PassPluginLibraryInfo get_api_gen_plugin_info() {
  return {LLVM_PLUGIN_API_VERSION, "ApiGenerator", LLVM_VERSION_STRING,
          [](PassBuilder &pb) {
            pb.registerPipelineParsingCallback(
                [&](StringRef name, FunctionPassManager &fpm,
                    ArrayRef<PassBuilder::PipelineElement>) {
                  if (name != "print<llvm-api-gen>")
                    return false;
                  fpm.addPass(lag::api_gen_pass());
                  return true;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return get_api_gen_plugin_info();
}
