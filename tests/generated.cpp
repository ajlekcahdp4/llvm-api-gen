#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>

#include <llvm/Support/TargetSelect.h>

using namespace llvm;

void foo(LLVMContext &Ctx, Module &M) {
  IRBuilder builder(Ctx);
  auto *type_0x000000002F7F93C8 = Type::getVoidTy(Ctx);
  auto *ret_type_0 = type_0x000000002F7F93C8;
  std::vector<Type *> args_0;
  auto *type_0x000000002F7F9560 = Type::getIntNTy(Ctx, 64);
  args_0.push_back(type_0x000000002F7F9560);
  auto *type_0x000000002F7FDE30 = PointerType::get(Ctx, 0);
  args_0.push_back(type_0x000000002F7FDE30);
  auto *func_type_0 = FunctionType::get(ret_type_0, args_0, false);
  auto *func_0 = Function::Create(func_type_0, Function::ExternalLinkage,
                                  "llvm.lifetime.start.p0", M);
  auto *ret_type_1 = type_0x000000002F7F93C8;
  std::vector<Type *> args_1;
  args_1.push_back(type_0x000000002F7FDE30);
  auto *type_0x000000002F7F9518 = Type::getIntNTy(Ctx, 8);
  args_1.push_back(type_0x000000002F7F9518);
  args_1.push_back(type_0x000000002F7F9560);
  auto *type_0x000000002F7F9500 = Type::getIntNTy(Ctx, 1);
  args_1.push_back(type_0x000000002F7F9500);
  auto *func_type_1 = FunctionType::get(ret_type_1, args_1, false);
  auto *func_1 = Function::Create(func_type_1, Function::ExternalLinkage,
                                  "llvm.memset.p0.i64", M);
  auto *ret_type_2 = type_0x000000002F7F93C8;
  std::vector<Type *> args_2;
  auto *type_0x000000002F7F9548 = Type::getIntNTy(Ctx, 32);
  args_2.push_back(type_0x000000002F7F9548);
  args_2.push_back(type_0x000000002F7F9548);
  args_2.push_back(type_0x000000002F7F9548);
  args_2.push_back(type_0x000000002F7F9548);
  auto *func_type_2 = FunctionType::get(ret_type_2, args_2, false);
  auto *func_2 =
      Function::Create(func_type_2, Function::ExternalLinkage, "init_sdl", M);
  auto *ret_type_3 = type_0x000000002F7F93C8;
  std::vector<Type *> args_3;
  auto *func_type_3 = FunctionType::get(ret_type_3, args_3, false);
  auto *func_3 = Function::Create(func_type_3, Function::ExternalLinkage,
                                  "destroy_sdl", M);
  auto *ret_type_4 = type_0x000000002F7F93C8;
  std::vector<Type *> args_4;
  args_4.push_back(type_0x000000002F7F9560);
  args_4.push_back(type_0x000000002F7FDE30);
  auto *func_type_4 = FunctionType::get(ret_type_4, args_4, false);
  auto *func_4 = Function::Create(func_type_4, Function::ExternalLinkage,
                                  "llvm.lifetime.end.p0", M);
  auto *ret_type_5 = type_0x000000002F7F93C8;
  std::vector<Type *> args_5;
  auto *func_type_5 = FunctionType::get(ret_type_5, args_5, false);
  auto *func_5 =
      Function::Create(func_type_5, Function::ExternalLinkage, "flush", M);
  auto *ret_type_6 = type_0x000000002F7F93C8;
  std::vector<Type *> args_6;
  args_6.push_back(type_0x000000002F7F9548);
  args_6.push_back(type_0x000000002F7F9548);
  args_6.push_back(type_0x000000002F7F9548);
  auto *func_type_6 = FunctionType::get(ret_type_6, args_6, false);
  auto *func_6 =
      Function::Create(func_type_6, Function::ExternalLinkage, "put_cell", M);
  auto *ret_type_7 = type_0x000000002F7F9548;
  std::vector<Type *> args_7;
  auto *func_type_7 = FunctionType::get(ret_type_7, args_7, false);
  auto *func_7 =
      Function::Create(func_type_7, Function::ExternalLinkage, "main", M);
  auto *bb_8 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_9 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_10 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_11 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_12 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_13 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_14 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_15 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_16 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_17 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_18 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_19 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_20 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_21 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_22 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_23 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_24 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_25 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_26 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_27 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_28 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_29 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_30 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_31 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_32 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_33 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_34 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_35 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_36 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_37 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_38 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_39 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_40 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_41 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_42 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_43 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_44 = BasicBlock::Create(Ctx, "", func_7);
  auto *bb_45 = BasicBlock::Create(Ctx, "", func_7);
  /*
    %1 = alloca [92 x [92 x i8]], align 16
  */
  builder.SetInsertPoint(bb_8);
  auto *type_0x000000002F7FDE50 = ArrayType::get(type_0x000000002F7F9518, 92);
  auto *type_0x000000002F7FDE80 = ArrayType::get(type_0x000000002F7FDE50, 92);
  auto *add_arg_46 = type_0x000000002F7FDE80;
  auto *op_0_46 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_46 = builder.CreateAlloca(add_arg_46, op_0_46);
  /*
    call void @llvm.lifetime.start.p0(i64 8464, ptr nonnull %1) #4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_47 = func_type_0;
  auto *op_1_47 = func_0;
  std::vector<Value *> op_2_47;
  auto *op_3_47 = ConstantInt::get(Ctx, APInt(64, 8464));
  auto *op_4_47 = instr_46;
  op_2_47.push_back(op_3_47);
  op_2_47.push_back(op_4_47);
  auto *instr_47 = builder.CreateCall(op_0_47, op_1_47, op_2_47);
  /*
    call void @llvm.memset.p0.i64(ptr noundef nonnull align 16
    dereferenceable(8464) %1, i8 0, i64 8464, i1 false)
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_48 = func_type_1;
  auto *op_1_48 = func_1;
  std::vector<Value *> op_2_48;
  auto *op_3_48 = instr_46;
  auto *op_4_48 = ConstantInt::get(Ctx, APInt(8, 0));
  auto *op_5_48 = ConstantInt::get(Ctx, APInt(64, 8464));
  auto *op_6_48 = ConstantInt::get(Ctx, APInt(1, 0));
  op_2_48.push_back(op_3_48);
  op_2_48.push_back(op_4_48);
  op_2_48.push_back(op_5_48);
  op_2_48.push_back(op_6_48);
  auto *instr_48 = builder.CreateCall(op_0_48, op_1_48, op_2_48);
  /*
    %2 = getelementptr inbounds [92 x [92 x i8]], ptr %1, i64 0, i64 46, i64 47
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_49 = type_0x000000002F7FDE80;
  auto *op_1_49 = instr_46;
  std::vector<Value *> op_2_49;
  auto *op_3_49 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *op_4_49 = ConstantInt::get(Ctx, APInt(64, 46));
  auto *op_5_49 = ConstantInt::get(Ctx, APInt(64, 47));
  op_2_49.push_back(op_3_49);
  op_2_49.push_back(op_4_49);
  op_2_49.push_back(op_5_49);
  auto *instr_49 = builder.CreateGEP(op_0_49, op_1_49, op_2_49);
  dyn_cast<Instruction>(instr_49)->setHasNoUnsignedWrap();
  /*
    store i8 1, ptr %2, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_50 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *op_1_50 = instr_49;
  auto *instr_50 = builder.CreateStore(op_0_50, op_1_50);
  /*
    %3 = getelementptr inbounds [92 x [92 x i8]], ptr %1, i64 0, i64 46, i64 48
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_51 = type_0x000000002F7FDE80;
  auto *op_1_51 = instr_46;
  std::vector<Value *> op_2_51;
  auto *op_3_51 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *op_4_51 = ConstantInt::get(Ctx, APInt(64, 46));
  auto *op_5_51 = ConstantInt::get(Ctx, APInt(64, 48));
  op_2_51.push_back(op_3_51);
  op_2_51.push_back(op_4_51);
  op_2_51.push_back(op_5_51);
  auto *instr_51 = builder.CreateGEP(op_0_51, op_1_51, op_2_51);
  dyn_cast<Instruction>(instr_51)->setHasNoUnsignedWrap();
  /*
    store i8 1, ptr %3, align 8, !tbaa !4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_52 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *op_1_52 = instr_51;
  auto *instr_52 = builder.CreateStore(op_0_52, op_1_52);
  /*
    %4 = getelementptr inbounds [92 x [92 x i8]], ptr %1, i64 0, i64 46, i64 49
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_53 = type_0x000000002F7FDE80;
  auto *op_1_53 = instr_46;
  std::vector<Value *> op_2_53;
  auto *op_3_53 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *op_4_53 = ConstantInt::get(Ctx, APInt(64, 46));
  auto *op_5_53 = ConstantInt::get(Ctx, APInt(64, 49));
  op_2_53.push_back(op_3_53);
  op_2_53.push_back(op_4_53);
  op_2_53.push_back(op_5_53);
  auto *instr_53 = builder.CreateGEP(op_0_53, op_1_53, op_2_53);
  dyn_cast<Instruction>(instr_53)->setHasNoUnsignedWrap();
  /*
    store i8 1, ptr %4, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_54 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *op_1_54 = instr_53;
  auto *instr_54 = builder.CreateStore(op_0_54, op_1_54);
  /*
    %5 = getelementptr inbounds [92 x [92 x i8]], ptr %1, i64 0, i64 47, i64 46
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_55 = type_0x000000002F7FDE80;
  auto *op_1_55 = instr_46;
  std::vector<Value *> op_2_55;
  auto *op_3_55 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *op_4_55 = ConstantInt::get(Ctx, APInt(64, 47));
  auto *op_5_55 = ConstantInt::get(Ctx, APInt(64, 46));
  op_2_55.push_back(op_3_55);
  op_2_55.push_back(op_4_55);
  op_2_55.push_back(op_5_55);
  auto *instr_55 = builder.CreateGEP(op_0_55, op_1_55, op_2_55);
  dyn_cast<Instruction>(instr_55)->setHasNoUnsignedWrap();
  /*
    store i8 1, ptr %5, align 2, !tbaa !4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_56 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *op_1_56 = instr_55;
  auto *instr_56 = builder.CreateStore(op_0_56, op_1_56);
  /*
    %6 = getelementptr inbounds [92 x [92 x i8]], ptr %1, i64 0, i64 48, i64 46
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_57 = type_0x000000002F7FDE80;
  auto *op_1_57 = instr_46;
  std::vector<Value *> op_2_57;
  auto *op_3_57 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *op_4_57 = ConstantInt::get(Ctx, APInt(64, 48));
  auto *op_5_57 = ConstantInt::get(Ctx, APInt(64, 46));
  op_2_57.push_back(op_3_57);
  op_2_57.push_back(op_4_57);
  op_2_57.push_back(op_5_57);
  auto *instr_57 = builder.CreateGEP(op_0_57, op_1_57, op_2_57);
  dyn_cast<Instruction>(instr_57)->setHasNoUnsignedWrap();
  /*
    store i8 1, ptr %6, align 2, !tbaa !4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_58 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *op_1_58 = instr_57;
  auto *instr_58 = builder.CreateStore(op_0_58, op_1_58);
  /*
    %7 = getelementptr inbounds [92 x [92 x i8]], ptr %1, i64 0, i64 49, i64 46
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_59 = type_0x000000002F7FDE80;
  auto *op_1_59 = instr_46;
  std::vector<Value *> op_2_59;
  auto *op_3_59 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *op_4_59 = ConstantInt::get(Ctx, APInt(64, 49));
  auto *op_5_59 = ConstantInt::get(Ctx, APInt(64, 46));
  op_2_59.push_back(op_3_59);
  op_2_59.push_back(op_4_59);
  op_2_59.push_back(op_5_59);
  auto *instr_59 = builder.CreateGEP(op_0_59, op_1_59, op_2_59);
  dyn_cast<Instruction>(instr_59)->setHasNoUnsignedWrap();
  /*
    store i8 1, ptr %7, align 2, !tbaa !4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_60 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *op_1_60 = instr_59;
  auto *instr_60 = builder.CreateStore(op_0_60, op_1_60);
  /*
    tail call void @init_sdl(i32 noundef 920, i32 noundef 920, i32 noundef 10,
    i32 noundef 50) #4
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_61 = func_type_2;
  auto *op_1_61 = func_2;
  std::vector<Value *> op_2_61;
  auto *op_3_61 = ConstantInt::get(Ctx, APInt(32, 920));
  auto *op_4_61 = ConstantInt::get(Ctx, APInt(32, 920));
  auto *op_5_61 = ConstantInt::get(Ctx, APInt(32, 10));
  auto *op_6_61 = ConstantInt::get(Ctx, APInt(32, 50));
  op_2_61.push_back(op_3_61);
  op_2_61.push_back(op_4_61);
  op_2_61.push_back(op_5_61);
  op_2_61.push_back(op_6_61);
  auto *instr_61 = builder.CreateCall(op_0_61, op_1_61, op_2_61);
  /*
    br label %8
  */
  builder.SetInsertPoint(bb_8);
  auto *op_0_62 = bb_9;
  auto *instr_62 = builder.CreateBr(op_0_62);
  /*
    %9 = phi i32 [ 0, %0 ], [ %116, %115 ]
  */
  builder.SetInsertPoint(bb_9);
  auto *phi_ty_63 = type_0x000000002F7F9548;
  auto *phi_63 = builder.CreatePHI(phi_ty_63, 2, "");
  auto *instr_63 = phi_63;
  /*
    br label %11
  */
  builder.SetInsertPoint(bb_9);
  auto *op_0_64 = bb_11;
  auto *instr_64 = builder.CreateBr(op_0_64);
  /*
    tail call void (...) @destroy_sdl() #4
  */
  builder.SetInsertPoint(bb_10);
  auto *op_0_65 = func_type_3;
  auto *op_1_65 = func_3;
  std::vector<Value *> op_2_65;
  auto *instr_65 = builder.CreateCall(op_0_65, op_1_65, op_2_65);
  /*
    call void @llvm.lifetime.end.p0(i64 8464, ptr nonnull %1) #4
  */
  builder.SetInsertPoint(bb_10);
  auto *op_0_66 = func_type_4;
  auto *op_1_66 = func_4;
  std::vector<Value *> op_2_66;
  auto *op_3_66 = ConstantInt::get(Ctx, APInt(64, 8464));
  auto *op_4_66 = instr_46;
  op_2_66.push_back(op_3_66);
  op_2_66.push_back(op_4_66);
  auto *instr_66 = builder.CreateCall(op_0_66, op_1_66, op_2_66);
  /*
    ret i32 0
  */
  builder.SetInsertPoint(bb_10);
  auto *op_0_67 = ConstantInt::get(Ctx, APInt(32, 0));
  auto *instr_67 = builder.CreateRet(op_0_67);
  /*
    %12 = phi i64 [ 0, %8 ], [ %119, %118 ]
  */
  builder.SetInsertPoint(bb_11);
  auto *phi_ty_68 = type_0x000000002F7F9560;
  auto *phi_68 = builder.CreatePHI(phi_ty_68, 2, "");
  auto *instr_68 = phi_68;
  /*
    %13 = trunc i64 %12 to i32
  */
  builder.SetInsertPoint(bb_11);
  auto op_0_69 = Instruction::CastOps::Trunc;
  auto *op_1_69 = instr_68;
  auto *op_2_69 = type_0x000000002F7F9548;
  auto *instr_69 = builder.CreateCast(op_0_69, op_1_69, op_2_69);
  /*
    %14 = trunc i64 %12 to i32
  */
  builder.SetInsertPoint(bb_11);
  auto op_0_70 = Instruction::CastOps::Trunc;
  auto *op_1_70 = instr_68;
  auto *op_2_70 = type_0x000000002F7F9548;
  auto *instr_70 = builder.CreateCast(op_0_70, op_1_70, op_2_70);
  /*
    br label %121
  */
  builder.SetInsertPoint(bb_11);
  auto *op_0_71 = bb_42;
  auto *instr_71 = builder.CreateBr(op_0_71);
  /*
    tail call void (...) @flush() #4
  */
  builder.SetInsertPoint(bb_12);
  auto *op_0_72 = func_type_5;
  auto *op_1_72 = func_5;
  std::vector<Value *> op_2_72;
  auto *instr_72 = builder.CreateCall(op_0_72, op_1_72, op_2_72);
  /*
    br label %16
  */
  builder.SetInsertPoint(bb_12);
  auto *op_0_73 = bb_13;
  auto *instr_73 = builder.CreateBr(op_0_73);
  /*
    %17 = phi i64 [ 0, %15 ], [ %24, %23 ]
  */
  builder.SetInsertPoint(bb_13);
  auto *phi_ty_74 = type_0x000000002F7F9560;
  auto *phi_74 = builder.CreatePHI(phi_ty_74, 2, "");
  auto *instr_74 = phi_74;
  /*
    %18 = icmp eq i64 %17, 91
  */
  builder.SetInsertPoint(bb_13);
  auto op_0_75 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_75 = instr_74;
  auto *op_2_75 = ConstantInt::get(Ctx, APInt(64, 91));
  auto *instr_75 = builder.CreateICmp(op_0_75, op_1_75, op_2_75);
  /*
    %19 = icmp ne i64 %17, 0
  */
  builder.SetInsertPoint(bb_13);
  auto op_0_76 = CmpInst::Predicate::ICMP_NE;
  auto *op_1_76 = instr_74;
  auto *op_2_76 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *instr_76 = builder.CreateICmp(op_0_76, op_1_76, op_2_76);
  /*
    %20 = sext i1 %19 to i32
  */
  builder.SetInsertPoint(bb_13);
  auto op_0_77 = Instruction::CastOps::SExt;
  auto *op_1_77 = instr_76;
  auto *op_2_77 = type_0x000000002F7F9548;
  auto *instr_77 = builder.CreateCast(op_0_77, op_1_77, op_2_77);
  /*
    %21 = select i1 %18, i32 1, i32 2
  */
  builder.SetInsertPoint(bb_13);
  auto *op_0_78 = instr_75;
  auto *op_1_78 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *op_2_78 = ConstantInt::get(Ctx, APInt(32, 2));
  auto *instr_78 = builder.CreateSelect(op_0_78, op_1_78, op_2_78);
  /*
    %22 = trunc i64 %17 to i32
  */
  builder.SetInsertPoint(bb_13);
  auto op_0_79 = Instruction::CastOps::Trunc;
  auto *op_1_79 = instr_74;
  auto *op_2_79 = type_0x000000002F7F9548;
  auto *instr_79 = builder.CreateCast(op_0_79, op_1_79, op_2_79);
  /*
    br label %26
  */
  builder.SetInsertPoint(bb_13);
  auto *op_0_80 = bb_15;
  auto *instr_80 = builder.CreateBr(op_0_80);
  /*
    %24 = add nuw nsw i64 %17, 1
  */
  builder.SetInsertPoint(bb_14);
  auto *op_0_81 = instr_74;
  auto *op_1_81 = ConstantInt::get(Ctx, APInt(64, 1));
  auto *instr_81 = builder.CreateAdd(op_0_81, op_1_81);
  dyn_cast<Instruction>(instr_81)->setHasNoUnsignedWrap();
  dyn_cast<Instruction>(instr_81)->setHasNoSignedWrap();
  /*
    %25 = icmp eq i64 %24, 92
  */
  builder.SetInsertPoint(bb_14);
  auto op_0_82 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_82 = instr_81;
  auto *op_2_82 = ConstantInt::get(Ctx, APInt(64, 92));
  auto *instr_82 = builder.CreateICmp(op_0_82, op_1_82, op_2_82);
  /*
    br i1 %25, label %93, label %16, !llvm.loop !7
  */
  builder.SetInsertPoint(bb_14);
  auto *op_0_83 = instr_82;
  auto *op_1_83 = bb_13;
  auto *op_2_83 = bb_31;
  auto *instr_83 = builder.CreateCondBr(op_0_83, op_1_83, op_2_83);
  /*
    %27 = phi i64 [ 0, %16 ], [ %91, %90 ]
  */
  builder.SetInsertPoint(bb_15);
  auto *phi_ty_84 = type_0x000000002F7F9560;
  auto *phi_84 = builder.CreatePHI(phi_ty_84, 2, "");
  auto *instr_84 = phi_84;
  /*
    %28 = icmp ne i64 %27, 0
  */
  builder.SetInsertPoint(bb_15);
  auto op_0_85 = CmpInst::Predicate::ICMP_NE;
  auto *op_1_85 = instr_84;
  auto *op_2_85 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *instr_85 = builder.CreateICmp(op_0_85, op_1_85, op_2_85);
  /*
    %29 = sext i1 %28 to i32
  */
  builder.SetInsertPoint(bb_15);
  auto op_0_86 = Instruction::CastOps::SExt;
  auto *op_1_86 = instr_85;
  auto *op_2_86 = type_0x000000002F7F9548;
  auto *instr_86 = builder.CreateCast(op_0_86, op_1_86, op_2_86);
  /*
    %30 = icmp eq i64 %27, 91
  */
  builder.SetInsertPoint(bb_15);
  auto op_0_87 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_87 = instr_84;
  auto *op_2_87 = ConstantInt::get(Ctx, APInt(64, 91));
  auto *instr_87 = builder.CreateICmp(op_0_87, op_1_87, op_2_87);
  /*
    %31 = select i1 %30, i32 1, i32 2
  */
  builder.SetInsertPoint(bb_15);
  auto *op_0_88 = instr_87;
  auto *op_1_88 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *op_2_88 = ConstantInt::get(Ctx, APInt(32, 2));
  auto *instr_88 = builder.CreateSelect(op_0_88, op_1_88, op_2_88);
  /*
    %32 = trunc i64 %27 to i32
  */
  builder.SetInsertPoint(bb_15);
  auto op_0_89 = Instruction::CastOps::Trunc;
  auto *op_1_89 = instr_84;
  auto *op_2_89 = type_0x000000002F7F9548;
  auto *instr_89 = builder.CreateCast(op_0_89, op_1_89, op_2_89);
  /*
    %33 = sub nsw i32 %31, %29
  */
  builder.SetInsertPoint(bb_15);
  auto *op_0_90 = instr_88;
  auto *op_1_90 = instr_86;
  auto *instr_90 = builder.CreateSub(op_0_90, op_1_90);
  dyn_cast<Instruction>(instr_90)->setHasNoSignedWrap();
  /*
    %34 = and i32 %33, 1
  */
  builder.SetInsertPoint(bb_15);
  auto *op_0_91 = instr_90;
  auto *op_1_91 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_91 = builder.CreateAnd(op_0_91, op_1_91);
  /*
    %35 = icmp eq i32 %34, 0
  */
  builder.SetInsertPoint(bb_15);
  auto op_0_92 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_92 = instr_91;
  auto *op_2_92 = ConstantInt::get(Ctx, APInt(32, 0));
  auto *instr_92 = builder.CreateICmp(op_0_92, op_1_92, op_2_92);
  /*
    %36 = add nsw i32 %29, %32
  */
  builder.SetInsertPoint(bb_15);
  auto *op_0_93 = instr_86;
  auto *op_1_93 = instr_89;
  auto *instr_93 = builder.CreateAdd(op_0_93, op_1_93);
  dyn_cast<Instruction>(instr_93)->setHasNoSignedWrap();
  /*
    %37 = zext i32 %36 to i64
  */
  builder.SetInsertPoint(bb_15);
  auto op_0_94 = Instruction::CastOps::ZExt;
  auto *op_1_94 = instr_93;
  auto *op_2_94 = type_0x000000002F7F9560;
  auto *instr_94 = builder.CreateCast(op_0_94, op_1_94, op_2_94);
  /*
    %38 = xor i1 %28, true
  */
  builder.SetInsertPoint(bb_15);
  auto *op_0_95 = instr_85;
  auto *op_1_95 = ConstantInt::get(Ctx, APInt(1, 1));
  auto *instr_95 = builder.CreateXor(op_0_95, op_1_95);
  /*
    %39 = zext i1 %38 to i32
  */
  builder.SetInsertPoint(bb_15);
  auto op_0_96 = Instruction::CastOps::ZExt;
  auto *op_1_96 = instr_95;
  auto *op_2_96 = type_0x000000002F7F9548;
  auto *instr_96 = builder.CreateCast(op_0_96, op_1_96, op_2_96);
  /*
    br label %40
  */
  builder.SetInsertPoint(bb_15);
  auto *op_0_97 = bb_16;
  auto *instr_97 = builder.CreateBr(op_0_97);
  /*
    %41 = phi i32 [ %20, %26 ], [ %54, %53 ]
  */
  builder.SetInsertPoint(bb_16);
  auto *phi_ty_98 = type_0x000000002F7F9548;
  auto *phi_98 = builder.CreatePHI(phi_ty_98, 2, "");
  auto *instr_98 = phi_98;
  /*
    %42 = phi i32 [ 0, %26 ], [ %75, %53 ]
  */
  builder.SetInsertPoint(bb_16);
  auto *phi_ty_99 = type_0x000000002F7F9548;
  auto *phi_99 = builder.CreatePHI(phi_ty_99, 2, "");
  auto *instr_99 = phi_99;
  /*
    %43 = add nsw i32 %41, %22
  */
  builder.SetInsertPoint(bb_16);
  auto *op_0_100 = instr_98;
  auto *op_1_100 = instr_79;
  auto *instr_100 = builder.CreateAdd(op_0_100, op_1_100);
  dyn_cast<Instruction>(instr_100)->setHasNoSignedWrap();
  /*
    %44 = zext i32 %43 to i64
  */
  builder.SetInsertPoint(bb_16);
  auto op_0_101 = Instruction::CastOps::ZExt;
  auto *op_1_101 = instr_100;
  auto *op_2_101 = type_0x000000002F7F9560;
  auto *instr_101 = builder.CreateCast(op_0_101, op_1_101, op_2_101);
  /*
    br i1 %35, label %50, label %45
  */
  builder.SetInsertPoint(bb_16);
  auto *op_0_102 = instr_92;
  auto *op_1_102 = bb_17;
  auto *op_2_102 = bb_19;
  auto *instr_102 = builder.CreateCondBr(op_0_102, op_1_102, op_2_102);
  /*
    %46 = getelementptr [92 x i8], ptr %1, i64 %44, i64 %37
  */
  builder.SetInsertPoint(bb_17);
  auto *op_0_103 = type_0x000000002F7FDE50;
  auto *op_1_103 = instr_46;
  std::vector<Value *> op_2_103;
  auto *op_3_103 = instr_101;
  auto *op_4_103 = instr_94;
  op_2_103.push_back(op_3_103);
  op_2_103.push_back(op_4_103);
  auto *instr_103 = builder.CreateGEP(op_0_103, op_1_103, op_2_103);
  /*
    %47 = load i8, ptr %46, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_17);
  auto *op_0_104 = type_0x000000002F7F9518;
  auto *op_1_104 = instr_103;
  auto *instr_104 = builder.CreateLoad(op_0_104, op_1_104);
  /*
    switch i8 %47, label %50 [
      i8 1, label %48
      i8 3, label %48
    ]
  */
  builder.SetInsertPoint(bb_17);
  auto *op_0_105 = instr_104;
  auto *op_1_105 = bb_19;
  auto op_2_105 = 2;
  auto *instr_105 = builder.CreateSwitch(op_0_105, op_1_105, op_2_105);
  auto *op_3_105 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *case_cond_0_105 = op_3_105;
  auto *op_4_105 = bb_18;
  auto *case_dest_0_105 = op_4_105;
  instr_105->addCase(case_cond_0_105, case_dest_0_105);
  auto *op_5_105 = ConstantInt::get(Ctx, APInt(8, 3));
  auto *case_cond_1_105 = op_5_105;
  auto *op_6_105 = bb_18;
  auto *case_dest_1_105 = op_6_105;
  instr_105->addCase(case_cond_1_105, case_dest_1_105);
  /*
    %49 = add i32 %42, 1
  */
  builder.SetInsertPoint(bb_18);
  auto *op_0_106 = instr_99;
  auto *op_1_106 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_106 = builder.CreateAdd(op_0_106, op_1_106);
  /*
    br label %50
  */
  builder.SetInsertPoint(bb_18);
  auto *op_0_107 = bb_19;
  auto *instr_107 = builder.CreateBr(op_0_107);
  /*
    %51 = phi i32 [ %29, %40 ], [ %39, %48 ], [ %39, %45 ]
  */
  builder.SetInsertPoint(bb_19);
  auto *phi_ty_108 = type_0x000000002F7F9548;
  auto *phi_108 = builder.CreatePHI(phi_ty_108, 3, "");
  auto *instr_108 = phi_108;
  /*
    %52 = phi i32 [ %42, %40 ], [ %49, %48 ], [ %42, %45 ]
  */
  builder.SetInsertPoint(bb_19);
  auto *phi_ty_109 = type_0x000000002F7F9548;
  auto *phi_109 = builder.CreatePHI(phi_ty_109, 3, "");
  auto *instr_109 = phi_109;
  /*
    br label %56
  */
  builder.SetInsertPoint(bb_19);
  auto *op_0_110 = bb_21;
  auto *instr_110 = builder.CreateBr(op_0_110);
  /*
    %54 = add nsw i32 %41, 1
  */
  builder.SetInsertPoint(bb_20);
  auto *op_0_111 = instr_98;
  auto *op_1_111 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_111 = builder.CreateAdd(op_0_111, op_1_111);
  dyn_cast<Instruction>(instr_111)->setHasNoSignedWrap();
  /*
    %55 = icmp eq i32 %54, %21
  */
  builder.SetInsertPoint(bb_20);
  auto op_0_112 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_112 = instr_111;
  auto *op_2_112 = instr_78;
  auto *instr_112 = builder.CreateICmp(op_0_112, op_1_112, op_2_112);
  /*
    br i1 %55, label %78, label %40, !llvm.loop !9
  */
  builder.SetInsertPoint(bb_20);
  auto *op_0_113 = instr_112;
  auto *op_1_113 = bb_16;
  auto *op_2_113 = bb_26;
  auto *instr_113 = builder.CreateCondBr(op_0_113, op_1_113, op_2_113);
  /*
    %57 = phi i32 [ %51, %50 ], [ %76, %74 ]
  */
  builder.SetInsertPoint(bb_21);
  auto *phi_ty_114 = type_0x000000002F7F9548;
  auto *phi_114 = builder.CreatePHI(phi_ty_114, 2, "");
  auto *instr_114 = phi_114;
  /*
    %58 = phi i32 [ %52, %50 ], [ %75, %74 ]
  */
  builder.SetInsertPoint(bb_21);
  auto *phi_ty_115 = type_0x000000002F7F9548;
  auto *phi_115 = builder.CreatePHI(phi_ty_115, 2, "");
  auto *instr_115 = phi_115;
  /*
    %59 = add nsw i32 %57, %32
  */
  builder.SetInsertPoint(bb_21);
  auto *op_0_116 = instr_114;
  auto *op_1_116 = instr_89;
  auto *instr_116 = builder.CreateAdd(op_0_116, op_1_116);
  dyn_cast<Instruction>(instr_116)->setHasNoSignedWrap();
  /*
    %60 = zext i32 %59 to i64
  */
  builder.SetInsertPoint(bb_21);
  auto op_0_117 = Instruction::CastOps::ZExt;
  auto *op_1_117 = instr_116;
  auto *op_2_117 = type_0x000000002F7F9560;
  auto *instr_117 = builder.CreateCast(op_0_117, op_1_117, op_2_117);
  /*
    %61 = getelementptr [92 x i8], ptr %1, i64 %44, i64 %60
  */
  builder.SetInsertPoint(bb_21);
  auto *op_0_118 = type_0x000000002F7FDE50;
  auto *op_1_118 = instr_46;
  std::vector<Value *> op_2_118;
  auto *op_3_118 = instr_101;
  auto *op_4_118 = instr_117;
  op_2_118.push_back(op_3_118);
  op_2_118.push_back(op_4_118);
  auto *instr_118 = builder.CreateGEP(op_0_118, op_1_118, op_2_118);
  /*
    %62 = load i8, ptr %61, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_21);
  auto *op_0_119 = type_0x000000002F7F9518;
  auto *op_1_119 = instr_118;
  auto *instr_119 = builder.CreateLoad(op_0_119, op_1_119);
  /*
    switch i8 %62, label %65 [
      i8 1, label %63
      i8 3, label %63
    ]
  */
  builder.SetInsertPoint(bb_21);
  auto *op_0_120 = instr_119;
  auto *op_1_120 = bb_23;
  auto op_2_120 = 2;
  auto *instr_120 = builder.CreateSwitch(op_0_120, op_1_120, op_2_120);
  auto *op_3_120 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *case_cond_0_120 = op_3_120;
  auto *op_4_120 = bb_22;
  auto *case_dest_0_120 = op_4_120;
  instr_120->addCase(case_cond_0_120, case_dest_0_120);
  auto *op_5_120 = ConstantInt::get(Ctx, APInt(8, 3));
  auto *case_cond_1_120 = op_5_120;
  auto *op_6_120 = bb_22;
  auto *case_dest_1_120 = op_6_120;
  instr_120->addCase(case_cond_1_120, case_dest_1_120);
  /*
    %64 = add i32 %58, 1
  */
  builder.SetInsertPoint(bb_22);
  auto *op_0_121 = instr_115;
  auto *op_1_121 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_121 = builder.CreateAdd(op_0_121, op_1_121);
  /*
    br label %65
  */
  builder.SetInsertPoint(bb_22);
  auto *op_0_122 = bb_23;
  auto *instr_122 = builder.CreateBr(op_0_122);
  /*
    %66 = phi i32 [ %64, %63 ], [ %58, %56 ]
  */
  builder.SetInsertPoint(bb_23);
  auto *phi_ty_123 = type_0x000000002F7F9548;
  auto *phi_123 = builder.CreatePHI(phi_ty_123, 2, "");
  auto *instr_123 = phi_123;
  /*
    %67 = add nsw i32 %57, 1
  */
  builder.SetInsertPoint(bb_23);
  auto *op_0_124 = instr_114;
  auto *op_1_124 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_124 = builder.CreateAdd(op_0_124, op_1_124);
  dyn_cast<Instruction>(instr_124)->setHasNoSignedWrap();
  /*
    %68 = add nsw i32 %67, %32
  */
  builder.SetInsertPoint(bb_23);
  auto *op_0_125 = instr_124;
  auto *op_1_125 = instr_89;
  auto *instr_125 = builder.CreateAdd(op_0_125, op_1_125);
  dyn_cast<Instruction>(instr_125)->setHasNoSignedWrap();
  /*
    %69 = zext i32 %68 to i64
  */
  builder.SetInsertPoint(bb_23);
  auto op_0_126 = Instruction::CastOps::ZExt;
  auto *op_1_126 = instr_125;
  auto *op_2_126 = type_0x000000002F7F9560;
  auto *instr_126 = builder.CreateCast(op_0_126, op_1_126, op_2_126);
  /*
    %70 = getelementptr [92 x i8], ptr %1, i64 %44, i64 %69
  */
  builder.SetInsertPoint(bb_23);
  auto *op_0_127 = type_0x000000002F7FDE50;
  auto *op_1_127 = instr_46;
  std::vector<Value *> op_2_127;
  auto *op_3_127 = instr_101;
  auto *op_4_127 = instr_126;
  op_2_127.push_back(op_3_127);
  op_2_127.push_back(op_4_127);
  auto *instr_127 = builder.CreateGEP(op_0_127, op_1_127, op_2_127);
  /*
    %71 = load i8, ptr %70, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_23);
  auto *op_0_128 = type_0x000000002F7F9518;
  auto *op_1_128 = instr_127;
  auto *instr_128 = builder.CreateLoad(op_0_128, op_1_128);
  /*
    switch i8 %71, label %74 [
      i8 1, label %72
      i8 3, label %72
    ]
  */
  builder.SetInsertPoint(bb_23);
  auto *op_0_129 = instr_128;
  auto *op_1_129 = bb_25;
  auto op_2_129 = 2;
  auto *instr_129 = builder.CreateSwitch(op_0_129, op_1_129, op_2_129);
  auto *op_3_129 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *case_cond_0_129 = op_3_129;
  auto *op_4_129 = bb_24;
  auto *case_dest_0_129 = op_4_129;
  instr_129->addCase(case_cond_0_129, case_dest_0_129);
  auto *op_5_129 = ConstantInt::get(Ctx, APInt(8, 3));
  auto *case_cond_1_129 = op_5_129;
  auto *op_6_129 = bb_24;
  auto *case_dest_1_129 = op_6_129;
  instr_129->addCase(case_cond_1_129, case_dest_1_129);
  /*
    %73 = add i32 %66, 1
  */
  builder.SetInsertPoint(bb_24);
  auto *op_0_130 = instr_123;
  auto *op_1_130 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_130 = builder.CreateAdd(op_0_130, op_1_130);
  /*
    br label %74
  */
  builder.SetInsertPoint(bb_24);
  auto *op_0_131 = bb_25;
  auto *instr_131 = builder.CreateBr(op_0_131);
  /*
    %75 = phi i32 [ %73, %72 ], [ %66, %65 ]
  */
  builder.SetInsertPoint(bb_25);
  auto *phi_ty_132 = type_0x000000002F7F9548;
  auto *phi_132 = builder.CreatePHI(phi_ty_132, 2, "");
  auto *instr_132 = phi_132;
  /*
    %76 = add nsw i32 %57, 2
  */
  builder.SetInsertPoint(bb_25);
  auto *op_0_133 = instr_114;
  auto *op_1_133 = ConstantInt::get(Ctx, APInt(32, 2));
  auto *instr_133 = builder.CreateAdd(op_0_133, op_1_133);
  dyn_cast<Instruction>(instr_133)->setHasNoSignedWrap();
  /*
    %77 = icmp eq i32 %76, %31
  */
  builder.SetInsertPoint(bb_25);
  auto op_0_134 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_134 = instr_133;
  auto *op_2_134 = instr_88;
  auto *instr_134 = builder.CreateICmp(op_0_134, op_1_134, op_2_134);
  /*
    br i1 %77, label %53, label %56, !llvm.loop !10
  */
  builder.SetInsertPoint(bb_25);
  auto *op_0_135 = instr_134;
  auto *op_1_135 = bb_21;
  auto *op_2_135 = bb_20;
  auto *instr_135 = builder.CreateCondBr(op_0_135, op_1_135, op_2_135);
  /*
    %79 = getelementptr [92 x i8], ptr %1, i64 %17, i64 %27
  */
  builder.SetInsertPoint(bb_26);
  auto *op_0_136 = type_0x000000002F7FDE50;
  auto *op_1_136 = instr_46;
  std::vector<Value *> op_2_136;
  auto *op_3_136 = instr_74;
  auto *op_4_136 = instr_84;
  op_2_136.push_back(op_3_136);
  op_2_136.push_back(op_4_136);
  auto *instr_136 = builder.CreateGEP(op_0_136, op_1_136, op_2_136);
  /*
    %80 = load i8, ptr %79, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_26);
  auto *op_0_137 = type_0x000000002F7F9518;
  auto *op_1_137 = instr_136;
  auto *instr_137 = builder.CreateLoad(op_0_137, op_1_137);
  /*
    %81 = icmp eq i8 %80, 1
  */
  builder.SetInsertPoint(bb_26);
  auto op_0_138 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_138 = instr_137;
  auto *op_2_138 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *instr_138 = builder.CreateICmp(op_0_138, op_1_138, op_2_138);
  /*
    %82 = sext i1 %81 to i32
  */
  builder.SetInsertPoint(bb_26);
  auto op_0_139 = Instruction::CastOps::SExt;
  auto *op_1_139 = instr_138;
  auto *op_2_139 = type_0x000000002F7F9548;
  auto *instr_139 = builder.CreateCast(op_0_139, op_1_139, op_2_139);
  /*
    %83 = add i32 %75, %82
  */
  builder.SetInsertPoint(bb_26);
  auto *op_0_140 = instr_132;
  auto *op_1_140 = instr_139;
  auto *instr_140 = builder.CreateAdd(op_0_140, op_1_140);
  /*
    switch i8 %80, label %90 [
      i8 1, label %84
      i8 0, label %87
    ]
  */
  builder.SetInsertPoint(bb_26);
  auto *op_0_141 = instr_137;
  auto *op_1_141 = bb_30;
  auto op_2_141 = 2;
  auto *instr_141 = builder.CreateSwitch(op_0_141, op_1_141, op_2_141);
  auto *op_3_141 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *case_cond_0_141 = op_3_141;
  auto *op_4_141 = bb_27;
  auto *case_dest_0_141 = op_4_141;
  instr_141->addCase(case_cond_0_141, case_dest_0_141);
  auto *op_5_141 = ConstantInt::get(Ctx, APInt(8, 0));
  auto *case_cond_1_141 = op_5_141;
  auto *op_6_141 = bb_28;
  auto *case_dest_1_141 = op_6_141;
  instr_141->addCase(case_cond_1_141, case_dest_1_141);
  /*
    %85 = add i32 %83, -4
  */
  builder.SetInsertPoint(bb_27);
  auto *op_0_142 = instr_140;
  auto *op_1_142 = ConstantInt::get(Ctx, APInt(32, 4294967292));
  auto *instr_142 = builder.CreateAdd(op_0_142, op_1_142);
  /*
    %86 = icmp ult i32 %85, -2
  */
  builder.SetInsertPoint(bb_27);
  auto op_0_143 = CmpInst::Predicate::ICMP_ULT;
  auto *op_1_143 = instr_142;
  auto *op_2_143 = ConstantInt::get(Ctx, APInt(32, 4294967294));
  auto *instr_143 = builder.CreateICmp(op_0_143, op_1_143, op_2_143);
  /*
    br i1 %86, label %88, label %90
  */
  builder.SetInsertPoint(bb_27);
  auto *op_0_144 = instr_143;
  auto *op_1_144 = bb_30;
  auto *op_2_144 = bb_29;
  auto *instr_144 = builder.CreateCondBr(op_0_144, op_1_144, op_2_144);
  /*
    switch i32 %83, label %90 [
      i32 6, label %88
      i32 3, label %88
    ]
  */
  builder.SetInsertPoint(bb_28);
  auto *op_0_145 = instr_140;
  auto *op_1_145 = bb_30;
  auto op_2_145 = 2;
  auto *instr_145 = builder.CreateSwitch(op_0_145, op_1_145, op_2_145);
  auto *op_3_145 = ConstantInt::get(Ctx, APInt(32, 6));
  auto *case_cond_0_145 = op_3_145;
  auto *op_4_145 = bb_29;
  auto *case_dest_0_145 = op_4_145;
  instr_145->addCase(case_cond_0_145, case_dest_0_145);
  auto *op_5_145 = ConstantInt::get(Ctx, APInt(32, 3));
  auto *case_cond_1_145 = op_5_145;
  auto *op_6_145 = bb_29;
  auto *case_dest_1_145 = op_6_145;
  instr_145->addCase(case_cond_1_145, case_dest_1_145);
  /*
    %89 = phi i8 [ 3, %84 ], [ 2, %87 ], [ 2, %87 ]
  */
  builder.SetInsertPoint(bb_29);
  auto *phi_ty_146 = type_0x000000002F7F9518;
  auto *phi_146 = builder.CreatePHI(phi_ty_146, 3, "");
  auto *instr_146 = phi_146;
  /*
    store i8 %89, ptr %79, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_29);
  auto *op_0_147 = instr_146;
  auto *op_1_147 = instr_136;
  auto *instr_147 = builder.CreateStore(op_0_147, op_1_147);
  /*
    br label %90
  */
  builder.SetInsertPoint(bb_29);
  auto *op_0_148 = bb_30;
  auto *instr_148 = builder.CreateBr(op_0_148);
  /*
    %91 = add nuw nsw i64 %27, 1
  */
  builder.SetInsertPoint(bb_30);
  auto *op_0_149 = instr_84;
  auto *op_1_149 = ConstantInt::get(Ctx, APInt(64, 1));
  auto *instr_149 = builder.CreateAdd(op_0_149, op_1_149);
  dyn_cast<Instruction>(instr_149)->setHasNoUnsignedWrap();
  dyn_cast<Instruction>(instr_149)->setHasNoSignedWrap();
  /*
    %92 = icmp eq i64 %91, 92
  */
  builder.SetInsertPoint(bb_30);
  auto op_0_150 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_150 = instr_149;
  auto *op_2_150 = ConstantInt::get(Ctx, APInt(64, 92));
  auto *instr_150 = builder.CreateICmp(op_0_150, op_1_150, op_2_150);
  /*
    br i1 %92, label %23, label %26, !llvm.loop !11
  */
  builder.SetInsertPoint(bb_30);
  auto *op_0_151 = instr_150;
  auto *op_1_151 = bb_15;
  auto *op_2_151 = bb_14;
  auto *instr_151 = builder.CreateCondBr(op_0_151, op_1_151, op_2_151);
  /*
    %94 = phi i64 [ %96, %95 ], [ 0, %23 ]
  */
  builder.SetInsertPoint(bb_31);
  auto *phi_ty_152 = type_0x000000002F7F9560;
  auto *phi_152 = builder.CreatePHI(phi_ty_152, 2, "");
  auto *instr_152 = phi_152;
  /*
    br label %98
  */
  builder.SetInsertPoint(bb_31);
  auto *op_0_153 = bb_33;
  auto *instr_153 = builder.CreateBr(op_0_153);
  /*
    %96 = add nuw nsw i64 %94, 1
  */
  builder.SetInsertPoint(bb_32);
  auto *op_0_154 = instr_152;
  auto *op_1_154 = ConstantInt::get(Ctx, APInt(64, 1));
  auto *instr_154 = builder.CreateAdd(op_0_154, op_1_154);
  dyn_cast<Instruction>(instr_154)->setHasNoUnsignedWrap();
  dyn_cast<Instruction>(instr_154)->setHasNoSignedWrap();
  /*
    %97 = icmp eq i64 %96, 92
  */
  builder.SetInsertPoint(bb_32);
  auto op_0_155 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_155 = instr_154;
  auto *op_2_155 = ConstantInt::get(Ctx, APInt(64, 92));
  auto *instr_155 = builder.CreateICmp(op_0_155, op_1_155, op_2_155);
  /*
    br i1 %97, label %115, label %93, !llvm.loop !12
  */
  builder.SetInsertPoint(bb_32);
  auto *op_0_156 = instr_155;
  auto *op_1_156 = bb_31;
  auto *op_2_156 = bb_40;
  auto *instr_156 = builder.CreateCondBr(op_0_156, op_1_156, op_2_156);
  /*
    %99 = phi i64 [ 0, %93 ], [ %113, %112 ]
  */
  builder.SetInsertPoint(bb_33);
  auto *phi_ty_157 = type_0x000000002F7F9560;
  auto *phi_157 = builder.CreatePHI(phi_ty_157, 2, "");
  auto *instr_157 = phi_157;
  /*
    %100 = getelementptr [92 x i8], ptr %1, i64 %94, i64 %99
  */
  builder.SetInsertPoint(bb_33);
  auto *op_0_158 = type_0x000000002F7FDE50;
  auto *op_1_158 = instr_46;
  std::vector<Value *> op_2_158;
  auto *op_3_158 = instr_152;
  auto *op_4_158 = instr_157;
  op_2_158.push_back(op_3_158);
  op_2_158.push_back(op_4_158);
  auto *instr_158 = builder.CreateGEP(op_0_158, op_1_158, op_2_158);
  /*
    %101 = load i8, ptr %100, align 2, !tbaa !4
  */
  builder.SetInsertPoint(bb_33);
  auto *op_0_159 = type_0x000000002F7F9518;
  auto *op_1_159 = instr_158;
  auto *instr_159 = builder.CreateLoad(op_0_159, op_1_159);
  /*
    switch i8 %101, label %105 [
      i8 2, label %103
      i8 3, label %102
    ]
  */
  builder.SetInsertPoint(bb_33);
  auto *op_0_160 = instr_159;
  auto *op_1_160 = bb_36;
  auto op_2_160 = 2;
  auto *instr_160 = builder.CreateSwitch(op_0_160, op_1_160, op_2_160);
  auto *op_3_160 = ConstantInt::get(Ctx, APInt(8, 2));
  auto *case_cond_0_160 = op_3_160;
  auto *op_4_160 = bb_35;
  auto *case_dest_0_160 = op_4_160;
  instr_160->addCase(case_cond_0_160, case_dest_0_160);
  auto *op_5_160 = ConstantInt::get(Ctx, APInt(8, 3));
  auto *case_cond_1_160 = op_5_160;
  auto *op_6_160 = bb_34;
  auto *case_dest_1_160 = op_6_160;
  instr_160->addCase(case_cond_1_160, case_dest_1_160);
  /*
    br label %103
  */
  builder.SetInsertPoint(bb_34);
  auto *op_0_161 = bb_35;
  auto *instr_161 = builder.CreateBr(op_0_161);
  /*
    %104 = phi i8 [ 0, %102 ], [ 1, %98 ]
  */
  builder.SetInsertPoint(bb_35);
  auto *phi_ty_162 = type_0x000000002F7F9518;
  auto *phi_162 = builder.CreatePHI(phi_ty_162, 2, "");
  auto *instr_162 = phi_162;
  /*
    store i8 %104, ptr %100, align 2, !tbaa !4
  */
  builder.SetInsertPoint(bb_35);
  auto *op_0_163 = instr_162;
  auto *op_1_163 = instr_158;
  auto *instr_163 = builder.CreateStore(op_0_163, op_1_163);
  /*
    br label %105
  */
  builder.SetInsertPoint(bb_35);
  auto *op_0_164 = bb_36;
  auto *instr_164 = builder.CreateBr(op_0_164);
  /*
    %106 = or disjoint i64 %99, 1
  */
  builder.SetInsertPoint(bb_36);
  auto *op_0_165 = instr_157;
  auto *op_1_165 = ConstantInt::get(Ctx, APInt(64, 1));
  auto *instr_165 = builder.CreateOr(op_0_165, op_1_165);
  dyn_cast<Instruction>(instr_165)->setHasNoUnsignedWrap();
  /*
    %107 = getelementptr [92 x i8], ptr %1, i64 %94, i64 %106
  */
  builder.SetInsertPoint(bb_36);
  auto *op_0_166 = type_0x000000002F7FDE50;
  auto *op_1_166 = instr_46;
  std::vector<Value *> op_2_166;
  auto *op_3_166 = instr_152;
  auto *op_4_166 = instr_165;
  op_2_166.push_back(op_3_166);
  op_2_166.push_back(op_4_166);
  auto *instr_166 = builder.CreateGEP(op_0_166, op_1_166, op_2_166);
  /*
    %108 = load i8, ptr %107, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_36);
  auto *op_0_167 = type_0x000000002F7F9518;
  auto *op_1_167 = instr_166;
  auto *instr_167 = builder.CreateLoad(op_0_167, op_1_167);
  /*
    switch i8 %108, label %112 [
      i8 2, label %110
      i8 3, label %109
    ]
  */
  builder.SetInsertPoint(bb_36);
  auto *op_0_168 = instr_167;
  auto *op_1_168 = bb_39;
  auto op_2_168 = 2;
  auto *instr_168 = builder.CreateSwitch(op_0_168, op_1_168, op_2_168);
  auto *op_3_168 = ConstantInt::get(Ctx, APInt(8, 2));
  auto *case_cond_0_168 = op_3_168;
  auto *op_4_168 = bb_38;
  auto *case_dest_0_168 = op_4_168;
  instr_168->addCase(case_cond_0_168, case_dest_0_168);
  auto *op_5_168 = ConstantInt::get(Ctx, APInt(8, 3));
  auto *case_cond_1_168 = op_5_168;
  auto *op_6_168 = bb_37;
  auto *case_dest_1_168 = op_6_168;
  instr_168->addCase(case_cond_1_168, case_dest_1_168);
  /*
    br label %110
  */
  builder.SetInsertPoint(bb_37);
  auto *op_0_169 = bb_38;
  auto *instr_169 = builder.CreateBr(op_0_169);
  /*
    %111 = phi i8 [ 0, %109 ], [ 1, %105 ]
  */
  builder.SetInsertPoint(bb_38);
  auto *phi_ty_170 = type_0x000000002F7F9518;
  auto *phi_170 = builder.CreatePHI(phi_ty_170, 2, "");
  auto *instr_170 = phi_170;
  /*
    store i8 %111, ptr %107, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_38);
  auto *op_0_171 = instr_170;
  auto *op_1_171 = instr_166;
  auto *instr_171 = builder.CreateStore(op_0_171, op_1_171);
  /*
    br label %112
  */
  builder.SetInsertPoint(bb_38);
  auto *op_0_172 = bb_39;
  auto *instr_172 = builder.CreateBr(op_0_172);
  /*
    %113 = add nuw nsw i64 %99, 2
  */
  builder.SetInsertPoint(bb_39);
  auto *op_0_173 = instr_157;
  auto *op_1_173 = ConstantInt::get(Ctx, APInt(64, 2));
  auto *instr_173 = builder.CreateAdd(op_0_173, op_1_173);
  dyn_cast<Instruction>(instr_173)->setHasNoUnsignedWrap();
  dyn_cast<Instruction>(instr_173)->setHasNoSignedWrap();
  /*
    %114 = icmp eq i64 %113, 92
  */
  builder.SetInsertPoint(bb_39);
  auto op_0_174 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_174 = instr_173;
  auto *op_2_174 = ConstantInt::get(Ctx, APInt(64, 92));
  auto *instr_174 = builder.CreateICmp(op_0_174, op_1_174, op_2_174);
  /*
    br i1 %114, label %95, label %98, !llvm.loop !13
  */
  builder.SetInsertPoint(bb_39);
  auto *op_0_175 = instr_174;
  auto *op_1_175 = bb_33;
  auto *op_2_175 = bb_32;
  auto *instr_175 = builder.CreateCondBr(op_0_175, op_1_175, op_2_175);
  /*
    %116 = add nuw nsw i32 %9, 1
  */
  builder.SetInsertPoint(bb_40);
  auto *op_0_176 = instr_63;
  auto *op_1_176 = ConstantInt::get(Ctx, APInt(32, 1));
  auto *instr_176 = builder.CreateAdd(op_0_176, op_1_176);
  dyn_cast<Instruction>(instr_176)->setHasNoUnsignedWrap();
  dyn_cast<Instruction>(instr_176)->setHasNoSignedWrap();
  /*
    %117 = icmp eq i32 %116, 1000
  */
  builder.SetInsertPoint(bb_40);
  auto op_0_177 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_177 = instr_176;
  auto *op_2_177 = ConstantInt::get(Ctx, APInt(32, 1000));
  auto *instr_177 = builder.CreateICmp(op_0_177, op_1_177, op_2_177);
  /*
    br i1 %117, label %10, label %8, !llvm.loop !14
  */
  builder.SetInsertPoint(bb_40);
  auto *op_0_178 = instr_177;
  auto *op_1_178 = bb_9;
  auto *op_2_178 = bb_10;
  auto *instr_178 = builder.CreateCondBr(op_0_178, op_1_178, op_2_178);
  /*
    %119 = add nuw nsw i64 %12, 1
  */
  builder.SetInsertPoint(bb_41);
  auto *op_0_179 = instr_68;
  auto *op_1_179 = ConstantInt::get(Ctx, APInt(64, 1));
  auto *instr_179 = builder.CreateAdd(op_0_179, op_1_179);
  dyn_cast<Instruction>(instr_179)->setHasNoUnsignedWrap();
  dyn_cast<Instruction>(instr_179)->setHasNoSignedWrap();
  /*
    %120 = icmp eq i64 %119, 92
  */
  builder.SetInsertPoint(bb_41);
  auto op_0_180 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_180 = instr_179;
  auto *op_2_180 = ConstantInt::get(Ctx, APInt(64, 92));
  auto *instr_180 = builder.CreateICmp(op_0_180, op_1_180, op_2_180);
  /*
    br i1 %120, label %15, label %11, !llvm.loop !15
  */
  builder.SetInsertPoint(bb_41);
  auto *op_0_181 = instr_180;
  auto *op_1_181 = bb_11;
  auto *op_2_181 = bb_12;
  auto *instr_181 = builder.CreateCondBr(op_0_181, op_1_181, op_2_181);
  /*
    %122 = phi i64 [ 0, %11 ], [ %130, %129 ]
  */
  builder.SetInsertPoint(bb_42);
  auto *phi_ty_182 = type_0x000000002F7F9560;
  auto *phi_182 = builder.CreatePHI(phi_ty_182, 2, "");
  auto *instr_182 = phi_182;
  /*
    %123 = getelementptr [92 x [92 x i8]], ptr %1, i64 0, i64 %12, i64 %122
  */
  builder.SetInsertPoint(bb_42);
  auto *op_0_183 = type_0x000000002F7FDE80;
  auto *op_1_183 = instr_46;
  std::vector<Value *> op_2_183;
  auto *op_3_183 = ConstantInt::get(Ctx, APInt(64, 0));
  auto *op_4_183 = instr_68;
  auto *op_5_183 = instr_182;
  op_2_183.push_back(op_3_183);
  op_2_183.push_back(op_4_183);
  op_2_183.push_back(op_5_183);
  auto *instr_183 = builder.CreateGEP(op_0_183, op_1_183, op_2_183);
  /*
    %124 = load i8, ptr %123, align 1, !tbaa !4
  */
  builder.SetInsertPoint(bb_42);
  auto *op_0_184 = type_0x000000002F7F9518;
  auto *op_1_184 = instr_183;
  auto *instr_184 = builder.CreateLoad(op_0_184, op_1_184);
  /*
    %125 = icmp eq i8 %124, 1
  */
  builder.SetInsertPoint(bb_42);
  auto op_0_185 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_185 = instr_184;
  auto *op_2_185 = ConstantInt::get(Ctx, APInt(8, 1));
  auto *instr_185 = builder.CreateICmp(op_0_185, op_1_185, op_2_185);
  /*
    %126 = trunc i64 %122 to i32
  */
  builder.SetInsertPoint(bb_42);
  auto op_0_186 = Instruction::CastOps::Trunc;
  auto *op_1_186 = instr_182;
  auto *op_2_186 = type_0x000000002F7F9548;
  auto *instr_186 = builder.CreateCast(op_0_186, op_1_186, op_2_186);
  /*
    br i1 %125, label %127, label %128
  */
  builder.SetInsertPoint(bb_42);
  auto *op_0_187 = instr_185;
  auto *op_1_187 = bb_44;
  auto *op_2_187 = bb_43;
  auto *instr_187 = builder.CreateCondBr(op_0_187, op_1_187, op_2_187);
  /*
    tail call void @put_cell(i32 noundef %14, i32 noundef %126, i32 noundef
    16777215) #4
  */
  builder.SetInsertPoint(bb_43);
  auto *op_0_188 = func_type_6;
  auto *op_1_188 = func_6;
  std::vector<Value *> op_2_188;
  auto *op_3_188 = instr_70;
  auto *op_4_188 = instr_186;
  auto *op_5_188 = ConstantInt::get(Ctx, APInt(32, 16777215));
  op_2_188.push_back(op_3_188);
  op_2_188.push_back(op_4_188);
  op_2_188.push_back(op_5_188);
  auto *instr_188 = builder.CreateCall(op_0_188, op_1_188, op_2_188);
  /*
    br label %129
  */
  builder.SetInsertPoint(bb_43);
  auto *op_0_189 = bb_45;
  auto *instr_189 = builder.CreateBr(op_0_189);
  /*
    tail call void @put_cell(i32 noundef %13, i32 noundef %126, i32 noundef 0)
    #4
  */
  builder.SetInsertPoint(bb_44);
  auto *op_0_190 = func_type_6;
  auto *op_1_190 = func_6;
  std::vector<Value *> op_2_190;
  auto *op_3_190 = instr_69;
  auto *op_4_190 = instr_186;
  auto *op_5_190 = ConstantInt::get(Ctx, APInt(32, 0));
  op_2_190.push_back(op_3_190);
  op_2_190.push_back(op_4_190);
  op_2_190.push_back(op_5_190);
  auto *instr_190 = builder.CreateCall(op_0_190, op_1_190, op_2_190);
  /*
    br label %129
  */
  builder.SetInsertPoint(bb_44);
  auto *op_0_191 = bb_45;
  auto *instr_191 = builder.CreateBr(op_0_191);
  /*
    %130 = add nuw nsw i64 %122, 1
  */
  builder.SetInsertPoint(bb_45);
  auto *op_0_192 = instr_182;
  auto *op_1_192 = ConstantInt::get(Ctx, APInt(64, 1));
  auto *instr_192 = builder.CreateAdd(op_0_192, op_1_192);
  dyn_cast<Instruction>(instr_192)->setHasNoUnsignedWrap();
  dyn_cast<Instruction>(instr_192)->setHasNoSignedWrap();
  /*
    %131 = icmp eq i64 %130, 92
  */
  builder.SetInsertPoint(bb_45);
  auto op_0_193 = CmpInst::Predicate::ICMP_EQ;
  auto *op_1_193 = instr_192;
  auto *op_2_193 = ConstantInt::get(Ctx, APInt(64, 92));
  auto *instr_193 = builder.CreateICmp(op_0_193, op_1_193, op_2_193);
  /*
    br i1 %131, label %118, label %121, !llvm.loop !16
  */
  builder.SetInsertPoint(bb_45);
  auto *op_0_194 = instr_193;
  auto *op_1_194 = bb_42;
  auto *op_2_194 = bb_41;
  auto *instr_194 = builder.CreateCondBr(op_0_194, op_1_194, op_2_194);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_183));
  auto *op_0_182 = ConstantInt::get(Ctx, APInt(64, 0));
  phi_182->addIncoming(op_0_182, bb_11);
  auto *op_1_182 = instr_192;
  phi_182->addIncoming(op_1_182, bb_45);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_171));
  auto *op_0_170 = ConstantInt::get(Ctx, APInt(8, 0));
  phi_170->addIncoming(op_0_170, bb_37);
  auto *op_1_170 = ConstantInt::get(Ctx, APInt(8, 1));
  phi_170->addIncoming(op_1_170, bb_36);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_163));
  auto *op_0_162 = ConstantInt::get(Ctx, APInt(8, 0));
  phi_162->addIncoming(op_0_162, bb_34);
  auto *op_1_162 = ConstantInt::get(Ctx, APInt(8, 1));
  phi_162->addIncoming(op_1_162, bb_33);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_158));
  auto *op_0_157 = ConstantInt::get(Ctx, APInt(64, 0));
  phi_157->addIncoming(op_0_157, bb_31);
  auto *op_1_157 = instr_173;
  phi_157->addIncoming(op_1_157, bb_39);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_64));
  auto *op_0_63 = ConstantInt::get(Ctx, APInt(32, 0));
  phi_63->addIncoming(op_0_63, bb_8);
  auto *op_1_63 = instr_176;
  phi_63->addIncoming(op_1_63, bb_40);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_147));
  auto *op_0_146 = ConstantInt::get(Ctx, APInt(8, 3));
  phi_146->addIncoming(op_0_146, bb_27);
  auto *op_1_146 = ConstantInt::get(Ctx, APInt(8, 2));
  phi_146->addIncoming(op_1_146, bb_28);
  auto *op_2_146 = ConstantInt::get(Ctx, APInt(8, 2));
  phi_146->addIncoming(op_2_146, bb_28);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_69));
  auto *op_0_68 = ConstantInt::get(Ctx, APInt(64, 0));
  phi_68->addIncoming(op_0_68, bb_9);
  auto *op_1_68 = instr_179;
  phi_68->addIncoming(op_1_68, bb_41);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_75));
  auto *op_0_74 = ConstantInt::get(Ctx, APInt(64, 0));
  phi_74->addIncoming(op_0_74, bb_12);
  auto *op_1_74 = instr_81;
  phi_74->addIncoming(op_1_74, bb_14);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_133));
  auto *op_0_132 = instr_130;
  phi_132->addIncoming(op_0_132, bb_24);
  auto *op_1_132 = instr_123;
  phi_132->addIncoming(op_1_132, bb_23);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_85));
  auto *op_0_84 = ConstantInt::get(Ctx, APInt(64, 0));
  phi_84->addIncoming(op_0_84, bb_13);
  auto *op_1_84 = instr_149;
  phi_84->addIncoming(op_1_84, bb_30);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_99));
  auto *op_0_98 = instr_77;
  phi_98->addIncoming(op_0_98, bb_15);
  auto *op_1_98 = instr_111;
  phi_98->addIncoming(op_1_98, bb_20);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_153));
  auto *op_0_152 = instr_154;
  phi_152->addIncoming(op_0_152, bb_32);
  auto *op_1_152 = ConstantInt::get(Ctx, APInt(64, 0));
  phi_152->addIncoming(op_1_152, bb_14);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_100));
  auto *op_0_99 = ConstantInt::get(Ctx, APInt(32, 0));
  phi_99->addIncoming(op_0_99, bb_15);
  auto *op_1_99 = instr_132;
  phi_99->addIncoming(op_1_99, bb_20);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_109));
  auto *op_0_108 = instr_86;
  phi_108->addIncoming(op_0_108, bb_16);
  auto *op_1_108 = instr_96;
  phi_108->addIncoming(op_1_108, bb_18);
  auto *op_2_108 = instr_96;
  phi_108->addIncoming(op_2_108, bb_17);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_124));
  auto *op_0_123 = instr_121;
  phi_123->addIncoming(op_0_123, bb_22);
  auto *op_1_123 = instr_115;
  phi_123->addIncoming(op_1_123, bb_21);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_110));
  auto *op_0_109 = instr_99;
  phi_109->addIncoming(op_0_109, bb_16);
  auto *op_1_109 = instr_106;
  phi_109->addIncoming(op_1_109, bb_18);
  auto *op_2_109 = instr_99;
  phi_109->addIncoming(op_2_109, bb_17);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_115));
  auto *op_0_114 = instr_108;
  phi_114->addIncoming(op_0_114, bb_19);
  auto *op_1_114 = instr_133;
  phi_114->addIncoming(op_1_114, bb_25);
  builder.SetInsertPoint(dyn_cast<Instruction>(instr_116));
  auto *op_0_115 = instr_109;
  phi_115->addIncoming(op_0_115, bb_19);
  auto *op_1_115 = instr_132;
  phi_115->addIncoming(op_1_115, bb_25);
}

auto main() -> int {
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmPrinter();
  LLVMContext ctx;
  Module m("mymodule", ctx);
  foo(ctx, m);
  m.dump();
}
