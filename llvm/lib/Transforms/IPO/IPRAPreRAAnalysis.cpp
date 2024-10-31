//===-- IPRAPreRAAnalysis.cpp ---=========-----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// IPRAPreRAAnalysis implementation.
///
/// The purpose of this pass is to analyze register usage information pre RA.
//===----------------------------------------------------------------------===//


#include "llvm/Transforms/IPO/IPRAPreRAAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BuildLibCalls.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Support/Casting.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/LineIterator.h"


using namespace llvm;

#define DEBUG_TYPE "iprapreraanalysis"

static cl::opt<std::string>
    IPRAPreRAFunctionSymsFile("ipra-prera-function-syms-file",
                              cl::desc("File containing the symbo list"),
                              cl::init(""), cl::Hidden);

// First dry run the symbol list to get all symbols that have a definition and
// then use that pruned list.
static cl::opt<bool>
    IPRADryRun("ipra-dry-run", cl::desc("Dry run to get valid function names"),
               cl::init(false), cl::Hidden);


static unsigned int parseSymbolsFile(StringMap<unsigned> &FunctionSymsMap) {
  auto BufferOrErr = MemoryBuffer::getFile(IPRAPreRAFunctionSymsFile, true);
  std::error_code EC = BufferOrErr.getError();
  if (EC) {
    dbgs() << "Could not open remarks file: "  << EC.message();
    return 0;
  }
  line_iterator LineIt(*BufferOrErr.get(), /*SkipBlanks=*/true);
  unsigned int count = 0;
  for (; !LineIt.is_at_eof(); ++LineIt) {
    StringRef Line = *LineIt;
    FunctionSymsMap[Line.str()] = 0;
    count++;
  }
  // dbgs() << "IPRA: Returning count = " << count << " values\n";
  return count;
}

PreservedAnalyses IPRAPreRAAnalysisPass::run(Module &M,
                                             ModuleAnalysisManager &AM) {
  // dbgs() << "In IPRAPreRAAnalysis : " << IPRAPreRAFunctionSymsFile << " \n";
  
  StringMap<unsigned> FunctionSymsMap;
  
  unsigned int MapEleCount = 0;
  if (IPRAPreRAFunctionSymsFile != "") {
    MapEleCount = parseSymbolsFile(FunctionSymsMap);
    // dbgs() << "MapEleCount : " << MapEleCount << "\n";
  }
  
  if (MapEleCount == 0) return PreservedAnalyses::all();
    
  // The Dry Run must explicitly print out address taken functions so that
  // we can eliminate them.  Comdats might be address taken in one module and
  // not in the other module.
  if (IPRADryRun) {
    for (Function &F: M.functions()) {
      if (FunctionSymsMap.contains(F.getName()) && !F.isDeclaration()
          && !F.hasAddressTaken())
        dbgs() << "IPRA: " << F.getName() << "\n";
      if (FunctionSymsMap.contains(F.getName()) && F.hasAddressTaken())
        dbgs() << "IPRAAddressTaken: " << F.getName() << "\n";
    }
    return PreservedAnalyses::all();
  }

  bool Changed = false;
  for (Function &F : M.functions()) {
    // dbgs() << "Looking at function : " << F.getName() << "\n";
    if (FunctionSymsMap.contains(F.getName())) {
      if (F.hasAddressTaken()) {
        dbgs() << "IPRA: Still Has Address Taken:" << F.getName() << "\n";
        continue;
      }
      if (F.isDeclaration())
        dbgs() << "IPRA: Declaration of function: " << F.getName() << "\n";
      else
        dbgs() << "IPRA: Definition of function: " << F.getName() << "\n";     
      
      F.setCallingConv(CallingConv::PreserveNone);
      for (User *U : F.users()) {
        if (isa<BlockAddress>(U))
          continue;
        cast<CallBase>(U)->setCallingConv(CallingConv::PreserveNone);
      }
      Changed = true;
            
    }
  }
  if (Changed)
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

