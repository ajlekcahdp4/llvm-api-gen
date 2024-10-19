#include "llvm-api-gen/llvm-api-gen.h"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/raw_ostream.h>

#include <string>
#include <unordered_set>

namespace lag {
using namespace std::string_literals;

constexpr auto builder = "builder";

struct generation_context final {
  std::unordered_set<const Type *> defined_types;
  std::unordered_map<const Value *, unsigned> defined_values;
  std::unordered_map<const PHINode *, const Instruction *> phis;
};

std::string get_type_str(const Type &type, StringRef ctx_name,
                         generation_context &ctx) {
  std::string ret;
  raw_string_ostream os(ret);
  auto [It, Inserted] = ctx.defined_types.insert(&type);
  if (!Inserted)
    return "";
  switch (type.getTypeID()) {
  case Type::IntegerTyID: {
    auto num = cast<IntegerType>(&type)->getBitWidth();
    os << formatv("auto *type_{0} = Type::getIntNTy({1}, {2});\n", &type,
                  ctx_name, num);
    return ret;
  }
  case Type::VoidTyID:
    os << formatv("auto *type_{0} = Type::getVoidTy({1});\n", &type, ctx_name);
    return ret;
  case Type::PointerTyID: {
    auto *ptr_type = dyn_cast<PointerType>(&type);
    assert(ptr_type);
    os << formatv("auto *type_{0} = PointerType::get({1}, 0);\n", &type,
                  ctx_name);
    return ret;
  }
  case Type::ArrayTyID: {
    auto *array_type = dyn_cast<ArrayType>(&type);
    assert(array_type);
    auto *elem_type = array_type->getElementType();
    assert(elem_type);
    auto num = array_type->getNumElements();
    os << get_type_str(*elem_type, ctx_name, ctx);
    os << formatv("auto *type_{0} = ArrayType::get(type_{1}, {2});\n", &type,
                  elem_type, num);
    return ret;
  }
  default:
    errs() << "TYPE: ";
    type.print(errs());
    errs() << "\n";
    llvm_unreachable("Unsupported type encountered");
  }
}

std::string get_ret_type(const Function &f, generation_context &ctx) {
  auto *func_type = f.getFunctionType();
  assert(func_type);
  auto *ret_type = func_type->getReturnType();
  assert(ret_type);
  std::string tp;
  raw_string_ostream os(tp);
  os << get_type_str(*ret_type, "Ctx", ctx);
  os << formatv("auto *ret_type_{0} = type_{1};\n", &f, ret_type);
  return tp;
}

std::string get_args_types(const Function &f, generation_context &ctx) {
  std::string create_args;
  raw_string_ostream os(create_args);
  os << formatv("std::vector<Type*> args_{0};\n", &f);
  auto *func_type = f.getFunctionType();
  assert(func_type);
  for (auto *t : func_type->params()) {
    assert(t);
    os << get_type_str(*t, "Ctx", ctx);
    os << formatv("args_{0}.push_back(type_{1});\n", &f, t);
  }
  return create_args;
}

std::string get_func_type(const Function &f, generation_context &ctx) {
  std::string create_func_type;
  raw_string_ostream os(create_func_type);
  os << get_ret_type(f, ctx);
  os << get_args_types(f, ctx);
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
    CASE_INSTR(Load)
    CASE_INSTR(Store)
    CASE_INSTR(Alloca)
    CASE_INSTR(Call)
    CASE_INSTR(Switch)
    CASE_INSTR(PHI)
    CASE_INSTR(Unreachable)
  case Instruction::GetElementPtr:
    return "GEP";
  default:
    return "UNSUPPORTED";
    // llvm_unreachable("Unsupported instruction");
  }
}
#undef CASE_INSTR

void create_operand(const Value &v, const Value &parent, unsigned idx,
                    raw_ostream &os, generation_context &ctx) {
  if (auto *int_constant = dyn_cast<ConstantInt>(&v)) {
    os << formatv(
        "auto *op_{0}_{1} = ConstantInt::get(Ctx, APInt({2}, {3}));\n", idx,
        &parent, int_constant->getBitWidth(), int_constant->getZExtValue());
  } else if (auto *bb = dyn_cast<BasicBlock>(&v)) {
    os << formatv("auto *op_{0}_{1} = bb_{2};\n", idx, &parent, bb);
  } else if (auto *func = dyn_cast<Function>(&v)) {
    os << formatv("auto *op_{0}_{1} = func_{2};\n", idx, &parent, func);
  } else if (auto *instr = dyn_cast<Instruction>(&v)) {
    os << formatv("auto *op_{0}_{1} = instr_{2};\n", idx, &parent, instr);
  } else if (auto *gv = dyn_cast<GlobalVariable>(&v)) {
    auto *constant = gv->getInitializer();
    if (auto *const_str = dyn_cast<ConstantDataSequential>(constant)) {
      if (const_str->isString())
        os << formatv("auto *op_{0}_{1} = ConstantDataArray::getString(Ctx, "
                      "\"{2}\", true);\n",
                      idx, &parent, const_str->getAsString().drop_back());
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
// Handle PHI nodes last
void create_phi_node(const PHINode &phi, raw_ostream &os,
                     generation_context &ctx) {
  auto num_incoming = phi.getNumIncomingValues();
  auto *type = phi.getType();
  os << get_type_str(*type, "Ctx", ctx);
  os << formatv("auto *phi_ty_{0} = type_{1};\n", &phi, type);
  os << formatv("auto *phi_{0} = {1}.CreatePHI(phi_ty_{0}, {2}, \"\");\n", &phi,
                builder, num_incoming);
  for (auto &&[idx, pair] :
       enumerate(zip(phi.incoming_values(), phi.blocks()))) {
    auto &&[val, bb] = pair;
    create_operand(*val.get(), *static_cast<const Value *>(&phi), idx, os, ctx);
    os << formatv("phi_{0}->addIncoming(op_{1}_{2}, bb_{3});\n", &phi, idx,
                  static_cast<const Value *>(&phi), &bb);
  }
  os << formatv("auto *instr_{0} = phi_{1};\n", dyn_cast<Instruction>(&phi),
                &phi);
}

bool requires_special_handling(const Instruction &instr) {
  switch (instr.getOpcode()) {
  case Instruction::Alloca:
    return true;
  case Instruction::Call:
    return true;
  default:
    return false;
  }
}

void create_pre_args(const Instruction &instr, raw_ostream &os,
                     generation_context &ctx) {
  switch (instr.getOpcode()) {
  case Instruction::Alloca: {
    auto *alloca = dyn_cast<AllocaInst>(&instr);
    assert(alloca);
    auto *allocated_type = alloca->getAllocatedType();
    assert(allocated_type);
    os << get_type_str(*allocated_type, "Ctx", ctx);
    os << formatv("auto *add_arg_{0} = type_{1};\n", &instr, allocated_type);
    break;
  }
  default:
    llvm_unreachable("unknown special instr");
  }
}

void generate_call_create_instr(const Instruction &instr, raw_ostream &os,
                                generation_context &ctx,
                                std::optional<unsigned> num = std::nullopt) {
  os << formatv("auto *instr_{0} = {1}.Create{2}(", &instr, builder,
                get_instr_create_name(instr))
            .str();
  if (auto *_ = dyn_cast<AllocaInst>(&instr))
    os << formatv("add_arg_{0}, ", &instr);

  interleaveComma(
      map_range(llvm::index_range(0, num.value_or(instr.getNumOperands())),
                [&instr](auto idx) {
                  return formatv("op_{0}_{1}", idx,
                                 static_cast<const Value *>(&instr))
                      .str();
                }),
      os);
  os << formatv(");\n");
}

void generate_operands(const Instruction &instr, raw_ostream &os,
                       generation_context &ctx) {
  for (auto &&[idx, op] : enumerate(instr.operands())) {
    //   if (idx == 0) continue; // drop_begin segfaults
    auto *val = op.get();
    assert(val);
    create_operand(*val, *static_cast<const Value *>(&instr), idx, os, ctx);
  }
}

void generate_special_instr(const Instruction &instr, raw_ostream &os,
                            generation_context &ctx) {
  switch (instr.getOpcode()) {
  case Instruction::Alloca: {
    create_pre_args(instr, os, ctx);
    generate_operands(instr, os, ctx);
    generate_call_create_instr(instr, os, ctx);
    return;
  }
  case Instruction::Call: {
    auto is_function = [](auto &op) -> bool {
      return dyn_cast<Function>(op.get());
    };
    auto func_it = llvm::find_if(instr.operands(), is_function);
    assert(func_it != instr.operands().end());
    auto *func = dyn_cast<Function>(func_it->get());
    assert(func);
    unsigned idx = 0;
    os << formatv("auto *op_{0}_{1} = func_type_{2};\n", idx++,
                  static_cast<const Value *>(&instr), func);
    os << formatv("auto *op_{0}_{1} = func_{2};\n", idx++,
                  static_cast<const Value *>(&instr), func);
    os << formatv("std::vector<Value *> op_{0}_{1};\n", idx++,
                  static_cast<const Value *>(&instr));
    auto first_arg_idx = idx;
    auto non_functions =
        llvm::make_filter_range(instr.operands(), std::not_fn(is_function));
    for (auto &&op : non_functions) {
      auto *val = op.get();
      assert(val);
      create_operand(*val, *static_cast<const Value *>(&instr), idx++, os, ctx);
    }
    for (auto i = first_arg_idx; i < idx; ++i) {
      os << formatv("op_{0}_{1}.push_back(op_{2}_{1});\n", first_arg_idx - 1,
                    static_cast<const Value *>(&instr), i);
    }
    generate_call_create_instr(instr, os, ctx, first_arg_idx);
  }
  }
}

std::string create_instr(const Instruction &instr, generation_context &ctx) {
  std::string instr_str;
  raw_string_ostream os(instr_str);
  // os << "\n\nINSTR:\n";
  // instr.print(os);
  // os << "\n";
  if (auto *phi = dyn_cast<PHINode>(&instr)) {
    auto [it, inserted] = ctx.phis.try_emplace(phi, instr.getNextNode());
    assert(inserted);
    return instr_str;
  }
  if (requires_special_handling(instr)) {
    generate_special_instr(instr, os, ctx);
  } else {
    generate_operands(instr, os, ctx);
    generate_call_create_instr(instr, os, ctx);
  }
  return instr_str;
}

std::string create_bb(const BasicBlock &bb, generation_context &ctx) {
  auto *f = bb.getParent();
  assert(f);
  std::string bb_str;
  raw_string_ostream os(bb_str);
  os << formatv("auto *bb_{0} = BasicBlock::Create(Ctx, \"\", func_{1});\n",
                &bb, f);
  os << formatv("{0}.SetInsertPoint(bb_{1});\n", builder, &bb);

  for (auto &instr : bb) {
    os << create_instr(instr, ctx);
  }
  return bb_str;
}

std::string create_func(const Function &f, generation_context &ctx) {
  std::string func;
  raw_string_ostream os(func);
  os << get_func_type(f, ctx);
  os << formatv("auto *func_{0} = Function::Create(func_type_{0}, "
                "Function::ExternalLinkage, \"{1}\", M);\n",
                &f, f.getName())
            .str();
  for (auto &bb : f)
    os << create_bb(bb, ctx);
  return func;
}

PreservedAnalyses api_gen_pass::run(Function &f, FunctionAnalysisManager &) {
  std::unordered_set<std::string> visited;
  generation_context ctx;
  visited.insert(f.getName().str());
  auto *m = f.getParent();
  assert(m);
  for (auto &ff : m->getFunctionList()) {
    if (ff.getName() != f.getName() && !visited.contains(ff.getName().str()))
      os << create_func(ff, ctx);
  }
  os << create_func(f, ctx);
  for (auto [phi, ins] : ctx.phis) {
    assert(phi);
    assert(ins);
    os << formatv("{0}.SetInsertPoint(instr_{1});\n", builder, ins);
    create_phi_node(*phi, os, ctx);
  }
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
