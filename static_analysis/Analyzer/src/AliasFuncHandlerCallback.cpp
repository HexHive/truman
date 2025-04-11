#include "AliasFuncHandlerCallback.h"
#include "AliasObject.h"
#include "InstructionUtils.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace DRCHECKER {

#define DEBUG_CREATE_HEAP_OBJ

    void* AliasFuncHandlerCallback::handleAllocationFunction(CallInst &callInst, Function *targetFunction,
                                                            void *private_data) {
        // Just create a new object
        return createNewHeapObject(callInst, targetFunction, private_data);

    }

    void *AliasFuncHandlerCallback::handleDMAFunction(CallInst &callInst, Function *targetFunction, void *private_data) {
        return createDMAObject(callInst, targetFunction, private_data);
    }

    void* AliasFuncHandlerCallback::handleCustomFunction(CallInst &callInst, Function *targetFunction,
                                                        void *private_data) {
        // Create a new heap object
        return createNewHeapObject(callInst, targetFunction, private_data);

    }

    void *AliasFuncHandlerCallback::createDMAObject(CallInst &callInst, Function *targetFunction, void *private_data) {
        return NULL;
        auto *call_sites_context = (std::vector<Instruction *>*)private_data;
        auto *target_size = callInst.getArgOperand(1);
        auto *raw_op = InstructionUtils::stripAllCasts(callInst.getArgOperand(2), true);
        auto *phy_dma_addr = llvm::dyn_cast<llvm::Instruction>(raw_op);
        // auto *phy_dma_addr = &callInst;
        auto *obj_type = InstructionUtils::inferPointeeTy(phy_dma_addr);
        auto *target_obj = new FunctionArgument(
            phy_dma_addr, phy_dma_addr->getType(), callInst.getCalledFunction(), call_sites_context);
        // auto *target_obj = new HeapLocation(
        //     *phy_dma_addr, obj_type, call_sites_context, target_size, false);
        target_obj->is_initialized = true;
        target_obj->initializingInstructions.insert(phy_dma_addr);

        auto *prop_inst = new InstLoc(phy_dma_addr, call_sites_context);
        target_obj->setAsTaintSrc(prop_inst, true);
        auto *new_points_to = new PointerPointsTo(phy_dma_addr, target_obj, 0, prop_inst, false);
        auto *new_points_to_info = new std::set<PointerPointsTo *>();
        new_points_to_info->insert(new_points_to_info->end(), new_points_to);
        return new_points_to_info;
    }

    void AliasFuncHandlerCallback::setPrivateData(void *data) {
        this->currState = (GlobalState*)data;
    }

    void* AliasFuncHandlerCallback::createNewHeapObject(CallInst &callInst, Function *targetFunction,
                                                       void *private_data) {
        if (!targetFunction) {
#ifdef DEBUG_CREATE_HEAP_OBJ
            dbgs() << "AliasFuncHandlerCallback::createNewHeapObject(): null targetFunction!!\n";
#endif
            return nullptr;
        }
        std::vector<Instruction*> *callSitesContext = (std::vector<Instruction*>*)private_data;
        Value *targetSize = nullptr;
        // if the call is to kmalloc, get the size argument.
        if (this->targetChecker->is_kmalloc_function(targetFunction)) {
            targetSize = callInst.getArgOperand(0);
        }
        //HZ: allocation functions usually only return an i8* pointer, we'd better try best to infer the real
        //allocation type here from the context.
        //TODO: verify the inferred type w/ the "size" arg if available. 
        Type *objTy = InstructionUtils::inferPointeeTy(&callInst);
        if (!objTy) {
            //This is very unlikely...
#ifdef DEBUG_CREATE_HEAP_OBJ
            dbgs() << "AliasFuncHandlerCallback::createNewHeapObject(): failed to infer the return type!\n";
#endif
            objTy = targetFunction->getReturnType();
            if (objTy && objTy->isPointerTy()) {
                objTy = objTy->getPointerElementType();
            }
        }
#ifdef DEBUG_CREATE_HEAP_OBJ
        dbgs() << "AliasFuncHandlerCallback::createNewHeapObject(): heap obj type to create: " << InstructionUtils::getTypeStr(objTy) << "\n";
#endif
        AliasObject *targetObj = new HeapLocation(callInst, objTy, callSitesContext, targetSize,
                                                  this->targetChecker->is_kmalloc_function(targetFunction));
        if(this->targetChecker->is_kmalloc_function(targetFunction)) {
            // OK, this is kmalloc function, now check if this is kzmalloc?
            Value *kmalloc_flag = callInst.getArgOperand(1);
            RangeAnalysis::Range flag_range = this->currState->getRange(kmalloc_flag);
            if(flag_range.isBounded()) {
                uint64_t lb = flag_range.getLower().getZExtValue();
                uint64_t ub = flag_range.getUpper().getZExtValue();
                // These are the flag values given when kzalloc is called.
                if((lb & 0x8000) || (ub & 0x8000)) {
                    targetObj->is_initialized = true;
                    targetObj->initializingInstructions.insert(&callInst);
                }
            }
        } else {
            targetObj->is_initialized = true;
            targetObj->initializingInstructions.insert(&callInst);
        }

        //HZ: we also need to treat heap objects as taint source...
        InstLoc *propInst = new InstLoc(&callInst,callSitesContext);
        targetObj->setAsTaintSrc(propInst,true);

        PointerPointsTo *newPointsTo = new PointerPointsTo(&callInst,targetObj,0,propInst,false);
        std::set<PointerPointsTo*> *newPointsToInfo = new std::set<PointerPointsTo*>();
        newPointsToInfo->insert(newPointsToInfo->end(), newPointsTo);
        return newPointsToInfo;
    }
}
