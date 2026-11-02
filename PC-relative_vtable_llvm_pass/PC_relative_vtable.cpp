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
#include "llvm/Support/FileSystem.h"
#include <iostream>

using namespace llvm;

bool is_a_vtable(GlobalVariable &Global);

namespace
{
    struct PCRelativeVtable : public PassInfoMixin<PCRelativeVtable>
    {
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM)
        {
            //  This first part is here to fix all loads inside vtable and make them relative

            // Vector that stores old load instruction pointers to delete them later
            // We need to do this because removing a load instuction during looping through the iterator renders the iterator invalid and causes a crash
            std::vector<LoadInst *> old_load_instruction_to_delete;

            for (Function &F : M)
            {
                for (BasicBlock &BB : F)
                {
                    for (Instruction &I : BB)
                    {
                        // Checking if the instruction is a load instruction
                        if (isa<LoadInst>(I))
                        {
                            LoadInst *load_instruction = cast<LoadInst>(&I);

                            // Checking that the load instruction has !invariant_load metadata, which should be the case only for a load inside a vtable pointer
                            // Also checking that the instruction loads a ptr. This allows us to not modify access to the size and align field, since the load instructions to access these actually load a i64, not a ptr
                            if (load_instruction->hasMetadata(LLVMContext::MD_invariant_load) && load_instruction->getType()->isPointerTy())
                            {
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
                                        // Retrieve the value as an int
                                        uint64_t offset_uint = offset.getLimitedValue();

                                        // Retrieving i32 type
                                        Type *i32_type = Type::getInt32Ty(M.getContext());

                                        // Retrieving IRBuilder to build a new instruction. we use the load_instruction to build it because it also defines the insertion point, which is gonna be right before the load instruction
                                        IRBuilder builder(load_instruction);

                                        // Retrieving the @llvm.load.relative.i32(ptr, offset) intrinsic
                                        FunctionCallee callee = FunctionCallee(Intrinsic::getOrInsertDeclaration(&M, Intrinsic::load_relative, {i32_type}));

                                        // Fixing the offset, since the ABI has been changed
                                        uint64_t offset_fixed = offset_uint - (((offset_uint / 8) - 3) * 4);

                                        // Getting the constant value corresponding to the offset_fixed value
                                        Value *offset_value = ConstantInt::get(i32_type, offset_fixed);

                                        // Creating the instruction calling the intrinsic, with the pointer operand and offset retrieved from the getelementptr
                                        CallInst *load_relative_call = builder.CreateCall(callee, {pointer_operand, offset_value});

                                        // We simply replace all uses of the previous load instruction with the new call instruction to @llvm.load.relative.i32(ptr, offset) intrinsic
                                        load_instruction->replaceAllUsesWith(load_relative_call);

                                        // Pushing the old load instruction inside the vector to delete it after looping through every instructions
                                        old_load_instruction_to_delete.push_back(load_instruction);
                                    }
                                    else
                                    {
                                        // Printing a warning here, since from observation, we should never enter this case, but we still leave a warning to spot this problem if it happens
                                        errs() << "WARNING: the getelementptr used to compute the pointer to the function inside the vtable doesn't use a constant as index, which should not be the case for a vtable call" << "!\n";
                                    }
                                    // If the operand of the load  operation is not a getelementptr instruction, then it means it indexes at the very first field of the vtable, which is the drop function
                                }
                                // This else is here to handle the case where the ptr being loaded by the load instruction doesn't come from a getelementptr. It usually means that we actually load the drop function at offset 0 since we didin't have to offset inside the vtable via a getelementptr instruction
                                // Therefore, we do not have to fix the offset, we just pass 0 as the offset argument of the @llvm.load.relative.i32(ptr, offset) intrinsic
                                else
                                {
                                    // Retrieving i32 type
                                    Type *i32_type = Type::getInt32Ty(M.getContext());

                                    // Retrieving IRBuilder to build a new instruction
                                    IRBuilder builder(load_instruction);

                                    // Retrieving the @llvm.load.relative.i32(ptr, offset) instrinsic
                                    FunctionCallee callee = FunctionCallee(Intrinsic::getOrInsertDeclaration(&M, Intrinsic::load_relative, {i32_type}));

                                    // Retrieving the constant value 0 to not index inside the vtable ptr since we want the first entry, which is the drop function
                                    Value *offset_value = ConstantInt::get(i32_type, 0);

                                    // Creating the instruction calling the intrinsic, with the pointer operand and offset retrieved from the getelementptr
                                    CallInst *load_relative_call = builder.CreateCall(callee, {loaded_pointer, offset_value});

                                    load_instruction->replaceAllUsesWith(load_relative_call);

                                    old_load_instruction_to_delete.push_back(load_instruction);
                                }
                            }
                        }
                    }
                }
            }

            // Looping through every old load instruction in order to remove them from the module
            for (LoadInst *load_inst : old_load_instruction_to_delete)
            {
                if (load_inst->use_empty())
                {
                    load_inst->eraseFromParent();
                }
                else
                {
                    errs() << "WARNING: the load instruction used to compute the call to a vtable call is still used somewhere, even though we called replaceAllUsesWith on it" << "!\n";
                }
            }

            // This second part is to fix the vtable global values to change function pointers into offset relative from the vtable location inside the binary

            // Constructing a vector to gather old vtables' pointers to remove them after looping through the iterator
            // We need to do this because removing a vtable during looping through the iterator renders the iterator invalid and causes a crash
            std::vector<GlobalVariable *> old_vtable_to_delete;

            // Looping through the global variable of the module
            for (auto global_it = M.global_begin(); global_it != M.global_end(); ++global_it)
            {
                // Retrieving the current global variable
                GlobalVariable &G = *global_it;

                // Checking if the global is a vtable
                if (is_a_vtable(G))
                {
                    // Retrieving the type of the global variable
                    Type *G_value_type = G.getValueType();

                    // Vector use to gather new modified types
                    SmallVector<Type *, 0> structure_subtypes;

                    // This first part is here to modify the type of the global variable

                    // Checking if the type is a structure, which should be the case
                    if (G_value_type->isStructTy())
                    {
                        // Iterating over the subtypes
                        for (auto [index, subtype] : llvm::enumerate(llvm::make_range(G_value_type->subtype_begin(), G_value_type->subtype_end())))
                        {
                            // Checking for subtype id to be a pointer
                            if (subtype->isPointerTy())
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
                            else if (subtype->isArrayTy())
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
                            if (constant->getType()->isPointerTy())
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
                            else if (constant->getType()->isArrayTy())
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
                if (vtable->use_empty())
                {
                    vtable->eraseFromParent();
                }
                else
                {
                    errs() << "WARNING: the vtable is still used somewhere, even though we called replaceAllUsesWith on it" << "!\n";
                }
            }

            return PreservedAnalyses::all();
        }
    };
}

// Simple function that checks if a given global is a vtable.
// Either the global name starts with vtable or if it doesn't, the function checks that it has the layout of a vtable pointer
bool is_a_vtable(GlobalVariable &Global)
{
    // Retrieving the name and checking if it starts with 'vtable' string, since all vtable global values start with this prefix
    auto G_name = Global.getName();
    if (G_name.starts_with("vtable"))
    {
        return true;
    }
    // Checking if the layout is the same as a vtable layout
    else
    {
        // If the global has no initializer, it is not a vtable
        if (!Global.hasInitializer())
        {
            return false;
        }

        Constant *initializer = Global.getInitializer();
        Type *initializer_struct = initializer->getType();

        // Vtables are always struct type
        if (!initializer_struct->isStructTy())
        {
            return false;
        }
        else
        {
            if (isa<StructType>(initializer_struct))
            {
                StructType *struct_type = cast<StructType>(initializer_struct);

                // Checking that the structure holds at least 2 elements (This might be the drop function and the arrays [16 x i8] containing the size and align field, or the [24 x i8] array where the first 8 bytes are the drop function pointer set to null because there is no drop function and at least one function pointer)
                if (struct_type->getNumElements() < 2)
                {
                    return false;
                }
            }
        }

        bool is_vtable = true;
        bool is_first_element_drop_ptr = false;

        // Iterating over values inside the initializer of the current global value
        // We'll check the layout to see if it is a vtable
        for (auto [index, element] : llvm::enumerate(initializer->operand_values()))
        {
            // For the first element
            if (index == 0)
            {
                // Casting safely to a Constant
                if (isa<Constant>(element))
                {
                    Constant *constant = cast<Constant>(element);
                    Type *constant_type = constant->getType();

                    // It is either the drop function pointer
                    if (constant_type->isPointerTy())
                    {
                        // If the pointer is not a function pointer, as it should be because this is the drop function, it's not a vtable
                        if (!isa<Function>(constant))
                        {
                            is_vtable = false;
                            break;
                        }
                        else
                        {
                            // We set this to true to discern between the 2 possibility of the first element. This is used for the second element, since if the first element is the drop pointer,
                            // then the second must be the [16 x i8] array, and if the first element is the [24 x i8] array, then the second element must be a pointer to either a method of the trait or a pointer to the vtable of a SuperTrait
                            is_first_element_drop_ptr = true;
                        }
                    }
                    // Or the [24 x i8] array if the drop function pointer is null
                    else if (constant_type->isArrayTy())
                    {
                        if (isa<ArrayType>(constant_type))
                        {
                            ArrayType *array_type = cast<ArrayType>(constant_type);
                            Type *element_type = array_type->getElementType();
                            // We chack that the array is indeed the [24 x i8] array
                            if (array_type->getNumElements() != 24 || !array_type->getElementType()->isIntegerTy(8))
                            {
                                is_vtable = false;
                                break;
                            }
                        }
                    }
                    else
                    {
                        is_vtable = false;
                        break;
                    }
                }
                else
                {
                    is_vtable = false;
                    break;
                }
            }
            else if (index == 1)
            {
                // Casting safely to a Constant
                if (isa<Constant>(element))
                {
                    Constant *constant = cast<Constant>(element);

                    Type *constant_type = constant->getType();

                    // If the first element was the drop function pointer
                    if (is_first_element_drop_ptr)
                    {
                        // We check that the second element is the [16 x i8] array
                        if (constant_type->isArrayTy())
                        {
                            if (isa<ArrayType>(constant_type))
                            {
                                ArrayType *array_type = cast<ArrayType>(constant_type);
                                Type *element_type = array_type->getElementType();
                                if (array_type->getNumElements() != 16 || !array_type->getElementType()->isIntegerTy(8))
                                {
                                    is_vtable = false;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            is_vtable = false;
                            break;
                        }
                    }
                    // If the first element is the [24 x i8] array
                    else
                    {
                        // Then we check that the second element is a pointer, either to a method of the trait or a pointer to the vtable of a SuperTrait
                        if (!constant_type->isPointerTy())
                        {
                            is_vtable = false;
                            break;
                        }
                    }
                }
                else
                {
                    is_vtable = false;
                    break;
                }
            }
            // Any other element after the first 2 must be a pointer, either to a method of the trait or a pointer to the vtable of a SuperTrait
            else
            {
                if (isa<Constant>(element))
                {
                    Constant *constant = cast<Constant>(element);

                    // Checking the type of the constant.
                    if (!constant->getType()->isPointerTy())
                    {
                        is_vtable = false;
                        break;
                    }
                }
                else
                {
                    is_vtable = false;
                    break;
                }
            }
        }

        return is_vtable;
    }
}

// Function to register the pass correctly, at the start of the pipeline in order to be executed as soon as possible because some !invariant.load metadata on load instruction inside vtables might be removed by later passes
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "PC relative vtable pass",
        .PluginVersion = LLVM_VERSION_STRING,
        .RegisterPassBuilderCallbacks = [](PassBuilder &PB)
        {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level)
                {
                    MPM.addPass(PCRelativeVtable());
                });
        }};
}