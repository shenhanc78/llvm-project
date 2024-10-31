//===-- IPRAPreRAAnalysis.h - Infer implicit function attributes ---------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Append "preserve_none" to some function attributes.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IPO_IPRAPRERAANALYSIS_H
#define LLVM_TRANSFORMS_IPO_IPRAPRERAANALYSIS_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;

/// A pass which appends RegAlloc specific function attributes to 
/// function declarations and definitions.
struct IPRAPreRAAnalysisPass : PassInfoMixin<IPRAPreRAAnalysisPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

}

#endif // LLVM_TRANSFORMS_IPO_IPRAPRERAANALYSIS_H
