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

template <typename value_type> const Value *get_value(const value_type &v) {
  return static_cast<const Value *>(&v);
}

struct generation_context final {
  std::unordered_set<const Type *> defined_types;
  std::unordered_map<const Value *, unsigned> defined_values;
  std::unordered_map<const PHINode *, const Instruction *> phis;
  template <typename value_type> unsigned get_value_idx(const value_type &val) {
    auto [it, inserted] =
        defined_values.try_emplace(get_value(val), defined_values.size());
    return it->second;
  }
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
  os << formatv("auto *ret_type_{0} = type_{1};\n", ctx.get_value_idx(f),
                ret_type);
  return tp;
}

std::string get_args_types(const Function &f, generation_context &ctx) {
  std::string create_args;
  raw_string_ostream os(create_args);
  os << formatv("std::vector<Type*> args_{0};\n", ctx.get_value_idx(f));
  auto *func_type = f.getFunctionType();
  assert(func_type);
  for (auto *t : func_type->params()) {
    assert(t);
    os << get_type_str(*t, "Ctx", ctx);
    os << formatv("args_{0}.push_back(type_{1});\n", ctx.get_value_idx(f), t);
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
                ctx.get_value_idx(f))
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
    CASE_INSTR(Ret)
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
  case Instruction::Trunc:
  case Instruction::SExt:
  case Instruction::ZExt:
    return "Cast";
  case Instruction::Br: {
    auto *br = dyn_cast<BranchInst>(&instr);
    assert(br);
    if (br->isConditional())
      return "CondBr";
    return "Br";
  }
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
        ctx.get_value_idx(parent), int_constant->getBitWidth(),
        int_constant->getZExtValue());
  } else if (auto *bb = dyn_cast<BasicBlock>(&v)) {
    os << formatv("auto *op_{0}_{1} = bb_{2};\n", idx,
                  ctx.get_value_idx(parent), ctx.get_value_idx(*bb));
  } else if (auto *func = dyn_cast<Function>(&v)) {
    os << formatv("auto *op_{0}_{1} = func_{2};\n", idx,
                  ctx.get_value_idx(parent), ctx.get_value_idx(*func));
  } else if (auto *instr = dyn_cast<Instruction>(&v)) {
    os << formatv("auto *op_{0}_{1} = instr_{2};\n", idx,
                  ctx.get_value_idx(parent), ctx.get_value_idx(*instr));
  } else if (auto *gv = dyn_cast<GlobalVariable>(&v)) {
    auto *constant = gv->getInitializer();
    if (auto *const_str = dyn_cast<ConstantDataSequential>(constant)) {
      if (const_str->isString())
        os << formatv("auto *op_{0}_{1} = ConstantDataArray::getString(Ctx, "
                      "\"{2}\", true);\n",
                      idx, ctx.get_value_idx(parent),
                      const_str->getAsString().drop_back());
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
void fill_phi_node(const PHINode &phi, raw_ostream &os,
                   generation_context &ctx) {
  for (auto &&[idx, pair] :
       enumerate(zip(phi.incoming_values(), phi.blocks()))) {
    auto &&[val, bb] = pair;
    create_operand(*val.get(), *get_value(phi), idx, os, ctx);
    os << formatv("phi_{0}->addIncoming(op_{1}_{2}, bb_{3});\n",
                  ctx.get_value_idx(phi), idx, ctx.get_value_idx(phi),
                  ctx.get_value_idx(*bb));
  }
}

void declare_phi_node(const PHINode &phi, raw_ostream &os,
                      generation_context &ctx) {
  auto num_incoming = phi.getNumIncomingValues();
  auto *type = phi.getType();
  os << get_type_str(*type, "Ctx", ctx);
  os << formatv("auto *phi_ty_{0} = type_{1};\n", ctx.get_value_idx(phi), type);
  os << formatv("auto *phi_{0} = {1}.CreatePHI(phi_ty_{0}, {2}, \"\");\n",
                ctx.get_value_idx(phi), builder, num_incoming);
  os << formatv("auto *instr_{0} = phi_{0};\n", ctx.get_value_idx(phi));
}

bool requires_special_handling(const Instruction &instr) {
  switch (instr.getOpcode()) {
  case Instruction::Alloca:
  case Instruction::Call:
  case Instruction::GetElementPtr:
  case Instruction::Load:
  case Instruction::ICmp:
  case Instruction::Trunc:
  case Instruction::SExt:
  case Instruction::ZExt:
  case Instruction::Switch:
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
    os << formatv("auto *add_arg_{0} = type_{1};\n", ctx.get_value_idx(instr),
                  allocated_type);
    break;
  }
  default:
    llvm_unreachable("unknown special instr");
  }
}

void generate_call_create_instr(const Instruction &instr, raw_ostream &os,
                                generation_context &ctx,
                                std::optional<unsigned> num = std::nullopt) {
  os << formatv("auto *instr_{0} = {1}.Create{2}(", ctx.get_value_idx(instr),
                builder, get_instr_create_name(instr))
            .str();
  if (auto *_ = dyn_cast<AllocaInst>(&instr))
    os << formatv("add_arg_{0}, ", ctx.get_value_idx(instr));

  interleaveComma(
      map_range(
          llvm::index_range(0, num.value_or(instr.getNumOperands())),
          [&instr, &ctx](auto idx) {
            return formatv("op_{0}_{1}", idx, ctx.get_value_idx(instr)).str();
          }),
      os);
  os << formatv(");\n");
}

void generate_operands(const Instruction &instr, raw_ostream &os,
                       generation_context &ctx) {
  for (auto &&[idx, op] : enumerate(instr.operands())) {
    auto *val = op.get();
    assert(val);
    create_operand(*val, *static_cast<const Value *>(&instr), idx, os, ctx);
  }
}

#define CASE_PRED(name)                                                        \
  case CmpInst::Predicate::name:                                               \
    return "CmpInst::Predicate::" #name;

std::string get_cmp_predicate_name(CmpInst::Predicate pred) {
  // CmpInst::getPredicateName is not an option since we need enum member name
  // and not a pretty-print. I wish we had reflection in C++
  switch (pred) {
    CASE_PRED(ICMP_EQ)
    CASE_PRED(ICMP_NE)
    CASE_PRED(ICMP_SGE)
    CASE_PRED(ICMP_SGT)
    CASE_PRED(ICMP_SLE)
    CASE_PRED(ICMP_SLT)
    CASE_PRED(ICMP_UGE)
    CASE_PRED(ICMP_UGT)
    CASE_PRED(ICMP_ULE)
    CASE_PRED(ICMP_ULT)
  default:
    llvm_unreachable("unsupported CmpInst predicate");
  }
}
#undef CASE_PRED

#define CASE_CAST(name)                                                        \
  case Instruction::CastOps::name:                                             \
    return "Instruction::CastOps::" #name;

std::string get_cast_opcode(Instruction::CastOps op) {
  switch (op) {
    CASE_CAST(Trunc)
    CASE_CAST(ZExt)
    CASE_CAST(SExt)
  default:
    llvm_unreachable("unsupported cast opcode");
  }
}
#undef CASE_CAST

void generate_special_instr(const Instruction &instr, raw_ostream &os,
                            generation_context &ctx) {
  if (auto *alloca = dyn_cast<AllocaInst>(&instr)) {
    create_pre_args(instr, os, ctx);
    generate_operands(instr, os, ctx);
    generate_call_create_instr(instr, os, ctx);
    return;
  }
  if (auto *call = dyn_cast<CallInst>(&instr)) {
    auto is_function = [](auto &op) -> bool {
      return dyn_cast<Function>(op.get());
    };
    auto func_it = llvm::find_if(instr.operands(), is_function);
    assert(func_it != instr.operands().end());
    auto *func = dyn_cast<Function>(func_it->get());
    assert(func);
    unsigned idx = 0;
    os << formatv("auto *op_{0}_{1} = func_type_{2};\n", idx++,
                  ctx.get_value_idx(instr), ctx.get_value_idx(*func));
    os << formatv("auto *op_{0}_{1} = func_{2};\n", idx++,
                  ctx.get_value_idx(instr), ctx.get_value_idx(*func));
    os << formatv("std::vector<Value *> op_{0}_{1};\n", idx++,
                  ctx.get_value_idx(instr));
    auto first_arg_idx = idx;
    auto non_functions =
        llvm::make_filter_range(instr.operands(), std::not_fn(is_function));
    for (auto &&op : non_functions) {
      auto *val = op.get();
      assert(val);
      create_operand(*val, *get_value(instr), idx++, os, ctx);
    }
    for (auto i = first_arg_idx; i < idx; ++i) {
      os << formatv("op_{0}_{1}.push_back(op_{2}_{1});\n", first_arg_idx - 1,
                    ctx.get_value_idx(instr), i);
    }
    generate_call_create_instr(instr, os, ctx, first_arg_idx);
    return;
  }
  if (auto *gep = dyn_cast<GetElementPtrInst>(&instr)) {
    auto *pointee_type = gep->getSourceElementType();
    assert(pointee_type);
    os << get_type_str(*pointee_type, "Ctx", ctx);
    unsigned idx = 0;
    os << formatv("auto *op_{0}_{1} = type_{2};\n", idx++,
                  ctx.get_value_idx(instr), pointee_type);
    auto &&operands = instr.operands();
    assert(!operands.empty());
    auto *first_op = operands.begin();
    auto *src_instr = dyn_cast<Instruction>(first_op->get());
    assert(src_instr);
    os << formatv("auto *op_{0}_{1} = instr_{2};\n", idx++,
                  ctx.get_value_idx(instr), ctx.get_value_idx(*src_instr));
    auto array_idx = idx;
    os << formatv("std::vector<Value *> op_{0}_{1};\n", idx++,
                  ctx.get_value_idx(instr));
    for (auto &op : llvm::drop_begin(operands)) {
      auto *val = op.get();
      assert(val);
      create_operand(*val, *get_value(instr), idx++, os, ctx);
    }
    for (auto i = array_idx + 1; i < idx; ++i) {
      os << formatv("op_{0}_{1}.push_back(op_{2}_{1});\n", array_idx,
                    ctx.get_value_idx(instr), i);
    }
    generate_call_create_instr(instr, os, ctx, array_idx + 1);
    return;
  }
  if (auto *load = dyn_cast<LoadInst>(&instr)) {
    auto *type = load->getType();
    assert(type);
    os << get_type_str(*type, "Ctx", ctx);
    unsigned idx = 0;
    os << formatv("auto *op_{0}_{1} = type_{2};\n", idx++,
                  ctx.get_value_idx(instr), type);
    for (auto &op : load->operands()) {
      auto *val = op.get();
      assert(val);
      create_operand(*val, *get_value(instr), idx++, os, ctx);
    }
    generate_call_create_instr(instr, os, ctx, idx);
    return;
  }
  if (auto *icmp = dyn_cast<ICmpInst>(&instr)) {
    auto pred = icmp->getPredicate();
    unsigned idx = 0;
    os << formatv("auto op_{0}_{1} = {2};\n", idx++, ctx.get_value_idx(instr),
                  get_cmp_predicate_name(pred));
    for (auto &op : icmp->operands()) {
      auto *val = op.get();
      assert(val);
      create_operand(*val, *get_value(instr), idx++, os, ctx);
    }
    generate_call_create_instr(instr, os, ctx, idx);
    return;
  }
  if (auto *cast = dyn_cast<CastInst>(&instr)) {
    auto *type = cast->getDestTy();
    assert(type);
    auto opc = cast->getOpcode();
    unsigned idx = 0;
    os << formatv("auto op_{0}_{1} = {2};\n", idx++, ctx.get_value_idx(instr),
                  get_cast_opcode(opc));
    for (auto &op : cast->operands()) {
      auto *val = op.get();
      assert(val);
      create_operand(*val, *get_value(instr), idx++, os, ctx);
    }
    os << formatv("auto *op_{0}_{1} = type_{2};\n", idx++,
                  ctx.get_value_idx(instr), type);
    generate_call_create_instr(instr, os, ctx, idx);
    return;
  }
  if (auto *sw = dyn_cast<SwitchInst>(&instr)) {
    auto *cond = sw->getCondition();
    auto *def_dest = sw->getDefaultDest();
    unsigned idx = 0;
    create_operand(*cond, *get_value(instr), idx++, os, ctx);
    create_operand(*def_dest, *get_value(instr), idx++, os, ctx);
    os << formatv("auto op_{0}_{1} = {2};\n", idx++, ctx.get_value_idx(instr),
                  sw->getNumCases());
    generate_call_create_instr(instr, os, ctx, idx);
    for (auto &&[i, c] : enumerate(sw->cases())) {
      create_operand(*c.getCaseValue(), *get_value(instr), idx, os, ctx);
      os << formatv("auto *case_cond_{0}_{2} = op_{1}_{2};\n", i, idx++,
                    ctx.get_value_idx(instr));
      create_operand(*c.getCaseSuccessor(), *get_value(instr), idx, os, ctx);
      os << formatv("auto *case_dest_{0}_{2} = op_{1}_{2};\n", i, idx++,
                    ctx.get_value_idx(instr));
      os << formatv(
          "instr_{0}->addCase(case_cond_{1}_{0}, case_dest_{1}_{0});\n",
          ctx.get_value_idx(instr), i);
    }
    return;
  }
  llvm_unreachable("unknown special instr");
}

std::string create_instr(const Instruction &instr, generation_context &ctx) {
  std::string instr_str;
  raw_string_ostream os(instr_str);
  auto *bb = instr.getParent();
  os << formatv("{0}.SetInsertPoint(bb_{1});\n", builder,
                ctx.get_value_idx(*bb));
  if (auto *phi = dyn_cast<PHINode>(&instr)) {
    auto [it, inserted] = ctx.phis.try_emplace(phi, instr.getNextNode());
    assert(inserted);
    declare_phi_node(*phi, os, ctx);
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
  for (auto &instr : bb)
    os << create_instr(instr, ctx);
  return bb_str;
}

std::string create_func(const Function &f, generation_context &ctx) {
  std::string func;
  raw_string_ostream os(func);
  os << get_func_type(f, ctx);
  os << formatv("auto *func_{0} = Function::Create(func_type_{0}, "
                "Function::ExternalLinkage, \"{1}\", M);\n",
                ctx.get_value_idx(f), f.getName())
            .str();
  for (auto &&bb : f)
    os << formatv("auto *bb_{0} = BasicBlock::Create(Ctx, \"\", func_{1});\n",
                  ctx.get_value_idx(bb), ctx.get_value_idx(f));
  // FIXME: use BFS
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
    os << formatv("{0}.SetInsertPoint(dyn_cast<Instruction>(instr_{1}));\n",
                  builder, ctx.get_value_idx(*ins));
    fill_phi_node(*phi, os, ctx);
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
