#ifndef LLVM_TRANSFORMS_PRESERVENONEPASS_H
#define LLVM_TRANSFORMS_PRESERVENONEPASS_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class PreserveNonePass : public PassInfoMixin<PreserveNonePass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_PRESERVENONEPASS_H