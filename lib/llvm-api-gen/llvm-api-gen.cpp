#include "llvm-api-gen/llvm-api-gen.h"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/raw_ostream.h>

#include <string>

namespace lag {
using namespace std::string_literals;

constexpr auto builder = "builder";

std::string get_type_str(const Type &type, StringRef ctx_name) {
  switch (type.getTypeID()) {
  case Type::IntegerTyID: {
    auto num = cast<IntegerType>(&type)->getBitWidth();
    return formatv("Type::getIntNTy({0}, {1})", ctx_name, num).str();
  }
  default:
    llvm_unreachable("Unsupported type encountered");
  }
}

std::string get_ret_type(const Function &f) {
  auto *func_type = f.getFunctionType();
  assert(func_type);
  auto *ret_type = func_type->getReturnType();
  assert(ret_type);
  return formatv("auto *ret_type_{0} = {1};\n", &f,
                 get_type_str(*ret_type, "Ctx"))
      .str();
}

std::string get_args_types(const Function &f) {
  std::string create_args;
  raw_string_ostream os(create_args);
  os << formatv("std::vector<Type*> args_{0};\n", &f);
  auto *func_type = f.getFunctionType();
  assert(func_type);
  for (auto *t : func_type->params()) {
    assert(t);
    os << formatv("args_{0}.push_back({1});\n", f.getName(),
                  get_type_str(*t, "Ctx"))
              .str();
  }
  return create_args;
}

std::string get_func_type(const Function &f) {
  std::string create_func_type;
  raw_string_ostream os(create_func_type);
  os << get_ret_type(f);
  os << get_args_types(f);
  os << formatv("auto *func_type_{0} = FunctionType::get(ret_type_{0}, "
                "args_{0}, false);\n",
                &f)
            .str();
  return create_func_type;
}

#define CASE_INSTR(name)                                                       \
  case Instruction::name:                                                      \
    return #name;

std::string get_instr_create_name(const Instruction &instr) {
  switch (instr.getOpcode()) {
    CASE_INSTR(Sub)
    CASE_INSTR(Add)
    CASE_INSTR(Mul)
    CASE_INSTR(UDiv)
    CASE_INSTR(SDiv)
    CASE_INSTR(URem)
    CASE_INSTR(SRem)
    CASE_INSTR(Shl)
    CASE_INSTR(LShr)
    CASE_INSTR(AShr)
    CASE_INSTR(And)
    CASE_INSTR(Or)
    CASE_INSTR(Xor)
    CASE_INSTR(Trunc)
    CASE_INSTR(ZExt)
    CASE_INSTR(SExt)
    CASE_INSTR(Ret)
    CASE_INSTR(Br)
    CASE_INSTR(ICmp)
    CASE_INSTR(Select)
    CASE_INSTR(GetElementPtr)
    CASE_INSTR(Load)
    CASE_INSTR(Store)
    CASE_INSTR(Alloca)
    CASE_INSTR(Call)
    CASE_INSTR(Switch)
    CASE_INSTR(PHI)
    CASE_INSTR(Unreachable)
  default:
    return "UNSUPPORTED";
    // llvm_unreachable("Unsupported instruction");
  }
}
#undef CASE_INSTR

void create_operand(const Value &v, unsigned idx, raw_ostream &os) {
  if (auto *int_constant = dyn_cast<ConstantInt>(&v)) {
    os << formatv(
        "auto *op_{0}_{1} = ConstantInt::get(Ctx, APInt({2}, {3}));\n", idx, &v,
        int_constant->getBitWidth(), int_constant->getZExtValue());
  } else if (auto *bb = dyn_cast<BasicBlock>(&v)) {
    os << formatv("auto *op_{0}_{1} = bb_{2};\n", idx, &v, bb);
  } else if (auto *func = dyn_cast<Function>(&v)) {
    os << formatv("auto *op_{0}_{1} = func_{2};\n", idx, &v, func);
  } else if (auto *instr = dyn_cast<Instruction>(&v)) {
    os << formatv("auto *op_{0}_{1} = instr_{2};\n", idx, &v, instr);
  } else if (auto *gv = dyn_cast<GlobalVariable>(&v)) {
    auto *constant = gv->getInitializer();
    if (auto *const_str = dyn_cast<ConstantDataSequential>(constant)) {
      if (const_str->isString())
        os << formatv("auto *op_{0}_{1} = ConstantDataArray::getString(Ctx, "
                      "\"{2}\", true);\n",
                      idx, &v, const_str->getAsString().drop_back());
      else
        os << "UNKNOWN\n";
    }
    // os << formatv("auto *");
  } else {
    os << "UNKNOWN_" << idx << ": ";
    v.print(os);
    os << "\n";
  }
}

void create_phi_node(const PHINode &phi, raw_ostream &os) {
  auto num_incoming = phi.getNumIncomingValues();
  os << formatv("auto *phi_ty_{0} = {1};\n", &phi,
                get_type_str(*phi.getType(), "Ctx"));
  os << formatv("auto *phi_{0} = {1}.CreatePHI(phi_ty_{0}, {2}, \"\");\n", &phi,
                builder, num_incoming);
  for (auto &&[idx, pair] :
       enumerate(zip(phi.incoming_values(), phi.blocks()))) {
    auto &&[val, bb] = pair;
    create_operand(*val.get(), idx, os);
    os << formatv("phi_{0}->addIncoming(op_{1}_{2}, bb_{3});\n", &phi, idx,
                  val.get(), &bb);
  }
}

std::string create_instr(const Instruction &instr) {
  std::string instr_str;
  raw_string_ostream os(instr_str);
  // os << "\n\nINSTR:\n";
  // instr.print(os);
  // os << "\n";
  if (auto *phi = dyn_cast<PHINode>(&instr)) {
    create_phi_node(*phi, os);
    return instr_str;
  }

  for (auto &&[idx, op] : enumerate(instr.operands())) {
    //   if (idx == 0) continue; // drop_begin segfaults
    auto *val = op.get();
    assert(val);
    create_operand(*val, idx, os);
  }
  os << formatv("auto *instr_{0} = {1}.Create{2}(", &instr, builder,
                get_instr_create_name(instr))
            .str();
  interleaveComma(map_range(enumerate(instr.operands()),
                            [](auto &&pair) {
                              auto &&[idx, op] = pair;
                              return formatv("op_{0}_{1}", idx, op.get()).str();
                            }),
                  os);
  os << formatv(");\n");
  return instr_str;
}

std::string create_bb(const BasicBlock &bb) {
  auto *f = bb.getParent();
  assert(f);
  std::string bb_str;
  raw_string_ostream os(bb_str);
  os << formatv("auto *bb_{0} = BasicBlock::Create(Ctx, \"\", func_{1});\n",
                &bb, f);
  os << formatv("{0}.SetInsertPoint(bb_{1});\n", builder, &bb);

  for (auto &instr : bb) {
    os << create_instr(instr);
  }
  return bb_str;
}

std::string create_func(const Function &f) {
  std::string func;
  raw_string_ostream os(func);
  os << get_func_type(f);
  os << formatv("auto *func_{0} = Function::Create(func_type_{0}, "
                "Function::ExternalLinkage, \"{1}\", M);\n",
                &f, f.getName())
            .str();
  for (auto &bb : f)
    os << create_bb(bb);
  return func;
}

PreservedAnalyses api_gen_pass::run(Function &f, FunctionAnalysisManager &) {
  os << create_func(f);
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
                  fpm.addPass(lag::api_gen_pass(outs()));
                  return true;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return get_api_gen_plugin_info();
}
