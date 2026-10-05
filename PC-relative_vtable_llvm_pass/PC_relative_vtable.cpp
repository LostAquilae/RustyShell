#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include <iostream>

using namespace llvm;

namespace
{

    struct PCRelativeVtable : public PassInfoMixin<PCRelativeVtable>
    {
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM)
        {
            //  This first part is here to fix all vtable call and make them relative

            // Looping through functions, blocks and every instructions
            for (Function &F : M)
            {
                for (BasicBlock &BB : F)
                {
                    for (Instruction &I : BB)
                    {
                        // Checking if the instruction is a call instruction
                        if (isa<CallInst>(I))
                        {
                            CallInst &call_instruction = cast<CallInst>(I);

                            // Checking if the instruction is an indirect call instruction, which vtable call and function pointer call are
                            if (call_instruction.isIndirectCall())
                            {

                                // Retrieving the instruction's attributes
                                AttributeList attributes = call_instruction.getAttributes();
                                AttributeSet function_attributes = attributes.getFnAttrs();

                                // Checking if inlinehint and nounwind are present for the called function
                                // Function pointer calls only have the nounwind attribute, so we use the inlinehint
                                // attribute to discern vtable calls and function pointers calls
                                if (function_attributes.hasAttribute(Attribute::AttrKind::InlineHint) && function_attributes.hasAttribute(Attribute::AttrKind::NoUnwind))
                                {
                                    // Retrieving the operand (register) that is called
                                    Value *called_value = call_instruction.getCalledOperand();

                                    // Checking if the operand comes from a load instruction, which should be the case for a vtable call
                                    if (isa<LoadInst>(called_value))
                                    {
                                        LoadInst *load_instruction = cast<LoadInst>(called_value);

                                        // Retrieving the pointer being dereferenced by this load instruction
                                        Value *loaded_pointer = load_instruction->getPointerOperand();

                                        // Checking that this pointer comes from a getelmentptr instruction
                                        if (isa<GetElementPtrInst>(loaded_pointer))
                                        {
                                            GetElementPtrInst *get_elem_inst = cast<GetElementPtrInst>(loaded_pointer);

                                            // Getting the pointer which is being offseted in the getelementptr instruction
                                            Value *pointer_operand = get_elem_inst->getPointerOperand();

                                            // Retrieving the bit width used to index inside the operand of the getelementptr instruction
                                            auto data_layout = M.getDataLayout();
                                            APInt offset(data_layout.getIndexTypeSizeInBits(pointer_operand->getType()), 0);

                                            //  Retrieving the full offset used to index inside the pointer
                                            if (get_elem_inst->accumulateConstantOffset(data_layout, offset))
                                            {
                                                // Retrieving i32 type
                                                Type *i32_type = Type::getInt32Ty(M.getContext());

                                                // Retrieving IRBuilder to build a new instruction
                                                IRBuilder builder(&call_instruction);

                                                // Retrieving the @llvm.load.relative.i32(ptr, offset) instrinsic
                                                FunctionCallee callee = FunctionCallee(Intrinsic::getOrInsertDeclaration(&M, Intrinsic::load_relative, {i32_type}));

                                                // Retrieve the value as an int
                                                uint64_t offset_uint = offset.getLimitedValue();

                                                // Fixing the offset, since the ABI has been changed
                                                uint64_t offset_fixed = offset_uint - (((offset_uint / 8) - 3) * 4);

                                                // Getting the constant value corresponding to the offset_fixed value
                                                Value *offset_value = ConstantInt::get(i32_type, offset_fixed);

                                                // Creating the instruction calling the intrinsic, with the pointer operand and offset retrieved from the getelementptr
                                                CallInst *load_relative_call = builder.CreateCall(callee, {pointer_operand, offset_value});

                                                // Modifying the vtable call to now call the result of the constructed @llvm.load.relative.i32(ptr, offset) instruction
                                                call_instruction.setCalledOperand(load_relative_call);
                                            }
                                            else
                                            {
                                                // Printing a warning here, since from observation, we should never enter this case, but we still leave a warning to spot this problem if it happens
                                                errs() << "WARNING: the getelementptr used to compute the pointer to the function inside the vtable doesn't use a constant as index, which should not be the case for a vtable call" << "!\n";
                                            }
                                            // If the operand of the load  operation is not a getelementptr instruction, then it means it indexes at the very first field of the vtable, which is the drop function
                                        }
                                        else
                                        {
                                            // Retrieving i32 type
                                            Type *i32_type = Type::getInt32Ty(M.getContext());

                                            // Retrieving IRBuilder to build a new instruction
                                            IRBuilder builder(&call_instruction);

                                            // Retrieving the @llvm.load.relative.i32(ptr, offset) instrinsic
                                            FunctionCallee callee = FunctionCallee(Intrinsic::getOrInsertDeclaration(&M, Intrinsic::load_relative, {i32_type}));

                                            // Retrieving the constant value 0 to not index inside the vtable ptr since we want the first entry, which is the drop function
                                            Value *offset_value = ConstantInt::get(i32_type, 0);

                                            // Creating the instruction calling the intrinsic, with the pointer operand and offset retrieved from the getelementptr
                                            CallInst *load_relative_call = builder.CreateCall(callee, {loaded_pointer, offset_value});

                                            // Modifying the vtable call to now call the result of the constructed @llvm.load.relative.i32(ptr, offset) instruction
                                            call_instruction.setCalledOperand(load_relative_call);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // We don't need to remove the getelementptr and loadptr instruction that are now obsolete, since it will be done during link time optimization automatically.

            // This second part is to fix the vtable global values to change function pointers into offset relative from the vtable location inside the binary

            // Constructing a vector to gather old vtables' pointers to remove them after looping through the iterator
            // We need to do this because removing a vtable during looping through the iterator renders the iterator invalid and causes a crash
            std::vector<GlobalVariable *> old_vtable_to_delete;

            // Looping through the global variable of the module
            for (auto global_it = M.global_begin(); global_it != M.global_end(); ++global_it)
            {
                // Retrieving the current global variable
                GlobalVariable &G = *global_it;

                // Retrieving the name and checking if it starts with 'vtable' string, since all vtable global values start with this prefix
                auto G_name = G.getName();
                if (G_name.starts_with("vtable"))
                {
                    // Retrieving the type of the global variable
                    Type *G_value_type = G.getValueType();

                    // Retrieving the Type ID of the type
                    auto G_value_type_id = G_value_type->getTypeID();

                    // Vector use to gather new modified types
                    SmallVector<Type *, 0> structure_subtypes;

                    // This first part is here to modify the type of the global variable

                    // Checking if the type is a structure, which should be the case
                    if (G_value_type_id == Type::TypeID::StructTyID)
                    {
                        // Iterating over the subtypes
                        for (auto [index, subtype] : llvm::enumerate(llvm::make_range(G_value_type->subtype_begin(), G_value_type->subtype_end())))
                        {
                            // Getting the subtype id
                            auto subtype_id = subtype->getTypeID();

                            // Checking for subtype id to be a pointer
                            if (subtype_id == Type::TypeID::PointerTyID)
                            {
                                // Getting the i32 type
                                IntegerType *i32_type = Type::getInt32Ty(M.getContext());

                                // Pushing the i32 type into the vector
                                structure_subtypes.push_back(i32_type);

                                // If the ptr type is the first type in the structure, then we want to put padding to take 8 bytes instead of 4 with the i32 type
                                // This is because we don't modify code that want to access size and alignement field, so we can't change their offset in the structure
                                // Which would have been the case wiithout padding (size field at offset 4 instead of 8).
                                if (index == 0)
                                {
                                    // Constructing an arrya of 4 bytes for padding
                                    ArrayType *padding_array = ArrayType::get(Type::getInt8Ty(M.getContext()), 4);
                                    structure_subtypes.push_back(padding_array);
                                }
                                // Checking for subtype id to be an array
                            }
                            else if (subtype_id == Type::TypeID::ArrayTyID)
                            {
                                // If this is an array, it means it is size and align field, and we don't modify this
                                // When there is no drop function, then the array starts at the beginning of the structure and has
                                // 8 first bytes that are zeroed out to replace the drop function pointer. In this case, we also don't want to
                                // move anything, so we just leave the array as is
                                structure_subtypes.push_back(subtype);
                            }
                        }
                    }

                    // Constructing the new structure type with the modified subtypes
                    StructType *new_struct_type = StructType::get(M.getContext(), structure_subtypes);

                    // Creating the new type based on the old type, using the new modified type and a new name
                    GlobalVariable *new_global = new GlobalVariable(M, new_struct_type, G.isConstant(), G.getLinkage(), nullptr, G.getName() + ".new", &G, G.getThreadLocalMode(), G.getType()->getAddressSpace(), false);
                    // GlobalVariable* new_global = new GlobalVariable(M, new_struct_type, G.isConstant(), G.getLinkage(), G.getInitializer(), G.getName() + ".new", &G, G.getThreadLocalMode(), G.getType()->getAddressSpace(), false);

                    // Setting the same attributes of the old global to the new global
                    new_global->setUnnamedAddr(G.getUnnamedAddr());
                    new_global->setAlignment(G.getAlign());

                    // From now on, the goal is to modify the values used to initialize the global variable

                    // Retrieving the initializer of the old global variable
                    Constant *initializer = G.getInitializer();

                    // Creating a pointer to the vtable, since it will be used for every modification on function pointers initializers to compute the offset between function pointer and start of the vtable
                    Constant *ptr_to_i64_vtable = ConstantExpr::getPtrToInt(new_global, Type::getInt64Ty(M.getContext()));

                    // Vector used to gather new modified values to initialize the new global variable
                    SmallVector<Constant *, 0> structure_subconstant;

                    // Iterating over values inside the initializer of the old vtable
                    for (auto [index, element] : llvm::enumerate(initializer->operand_values()))
                    {
                        // Casting safely to a Constant
                        if (isa<Constant>(element))
                        {
                            Constant *constant = cast<Constant>(element);

                            // Checking the type of the constant. We want to modify pointers but not arrays
                            if (constant->getType()->getTypeID() == Type::PointerTyID)
                            {

                                // Modifying the pointer to become an offset from the vtable pointer

                                // Casting pointer to vtable function into a i64
                                Constant *ptr_to_i64_func = ConstantExpr::getPtrToInt(constant, Type::getInt64Ty(M.getContext()));

                                // Subbing the pointer to the function and the pointer to the vtable to get the offset
                                Constant *sub_func_vtable = ConstantExpr::getSub(ptr_to_i64_func, ptr_to_i64_vtable);

                                // Truncing the result into an i32. This can be done safely, since the resulting relocation type is a PC32 relative offset, which is always encoded on maximum 32 bits
                                Constant *i32_trunc_offset_func_vtable = ConstantExpr::getTrunc(sub_func_vtable, Type::getInt32Ty(M.getContext()));

                                // Adding the constant to vector for further constructing the initializer
                                structure_subconstant.push_back(i32_trunc_offset_func_vtable);

                                // If we are at the first pointer, meaning before size and align fields, we need to add the zeroed out 4 bytes array
                                if (index == 0)
                                {
                                    // Retrieving the type of a 4 bytes array
                                    ArrayType *padding_array = ArrayType::get(Type::getInt8Ty(M.getContext()), 4);

                                    // Creating the constant value zeroed out of a 4 byte array
                                    Constant *padding_null = Constant::getNullValue(padding_array);

                                    // Pushing the padding to the vector for later construction of the initializer
                                    structure_subconstant.push_back(padding_null);
                                }
                                // Checking for array type, we want to preserve it without modifying it
                            }
                            else if (constant->getType()->getTypeID() == Type::ArrayTyID)
                            {
                                // adding the array initializer unmodified
                                structure_subconstant.push_back(constant);
                            }
                        }
                    }

                    // Constructing the structure Constant from the subvalues inside the structure
                    Constant *constant_struct = ConstantStruct::get(new_struct_type, structure_subconstant);

                    // Setting the initializer of the new vtable to the newly constructed structure
                    new_global->setInitializer(constant_struct);

                    // Replace all uses of the old vtable with the new vtable
                    G.replaceAllUsesWith(new_global);

                    // Transferring the name of the old vtable to the new vtable
                    new_global->takeName(&G);

                    // Pushing the old vtable for further deletion to prevent iterator error when removing global variable while iterating over them
                    old_vtable_to_delete.push_back(&G);
                }
            }

            // Looping through every old vtable in order to remove them from the module
            for (GlobalVariable *vtable : old_vtable_to_delete)
            {
                vtable->eraseFromParent();
            }

            return PreservedAnalyses::all();
        };
    };

}

// Function to register the pass correctly and enable it upon correct name (relative-vtable)
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "PC relative vtable pass",
        .PluginVersion = LLVM_VERSION_STRING,
        .RegisterPassBuilderCallbacks = [](PassBuilder &PB)
        {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>)
                {
                    if (Name == "relative-vtable")
                    {
                        MPM.addPass(PCRelativeVtable());
                        return true;
                    }
                    return false;
                });
        }};
}
