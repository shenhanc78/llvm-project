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

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "llvm/Transforms/IPO/IPRAPreRAAnalysis.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Support/Casting.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/Path.h"

using namespace ::llvm;

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

static const std::string embedded_syms[] = {
  #include "llvm/Transforms/IPO/embedded_syms.h"
};

static unsigned int parseSymbolsFile(StringMap<unsigned> &FunctionSymsMap) {
  if (IPRAPreRAFunctionSymsFile == "__embedded__") {
    for (const auto &sym : embedded_syms)
      FunctionSymsMap[sym] = 0;
    // if (!IPRADryRun) {
    //   for (const auto &aks : address_taken_syms) {
    //     FunctionSymsMap.erase(aks);
    //   }
    //   for (const auto &tcs : tail_call_syms) {
    //     FunctionSymsMap.erase(tcs);
    //   }
    // }
    return FunctionSymsMap.size();
  }
  auto BufferOrErr = MemoryBuffer::getFile(IPRAPreRAFunctionSymsFile, true);
  auto EC = BufferOrErr.getError();
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
  StringMap<unsigned> FunctionSymsMap;

  unsigned int MapEleCount = 0;
  if (IPRAPreRAFunctionSymsFile != "") {
    MapEleCount = parseSymbolsFile(FunctionSymsMap);
    // dbgs() << "MapEleCount : " << MapEleCount << "\n";
    fprintf(stderr, "IPRA: MapEleCount: %d\n", MapEleCount);
  }

  if (!IPRADryRun && MapEleCount == 0) return PreservedAnalyses::all();

  // The Dry Run must explicitly print out address taken functions so that
  // we can eliminate them.  Comdats might be address taken in one module and
  // not in the other module.
  if (IPRADryRun) {
    for (Function &F : M.functions()) {

      llvm::StringRef cu_name = "";
      if (DISubprogram *subprogram = F.getSubprogram())
        if (llvm::DICompileUnit *comp_unit = subprogram->getUnit())
          cu_name =
              sys::path::remove_leading_dotslash(comp_unit->getFilename());
      std::string CUNameStr = cu_name.str();

      // if (!FunctionSymsMap.contains(F.getName())) continue;

      const std::string FName = F.getName().str();
      const char *FNameCStr = FName.c_str();

      // if (!F.isDeclaration() && !F.hasAddressTaken())
      //   fprintf(stderr, "IPRA: %s\n", FNameCStr);

      // if (F.hasAddressTaken())
      //   fprintf(stderr, "IPRA: Function: %s[%s] HasAddressTaken\n", FNameCStr,
      //           CUNameStr.c_str());

      bool must_tail_call = false;
      // Tailcall check 1.
      if (!F.isDeclaration()) {
        for (BasicBlock &B : F) {
          for (Instruction &I : B) {
            if (isa<CallInst>(I)) {
              CallInst *ci = cast<CallInst>(&I);
              if (ci->isMustTailCall()) {
                must_tail_call = true;
                break;
              }
            }
          }
          if (must_tail_call)
            break;
        }
      }
      // Tailcall check 2 and use sites check.
      bool all_uses_are_call = true;
      bool uses_are_indirect_call = false;
      for (User *U : F.users()) {
        if (isa<CallInst>(U)) {
          CallInst *ci = cast<CallInst>(U);
          if (ci->isMustTailCall()) {
            must_tail_call = true;
            break;
          } else if (ci->isIndirectCall()) {
            // Not likely to happen, but check
            uses_are_indirect_call = true;
            break;
          }
        } else {
          all_uses_are_call = false;
          break;
        }
      }
      if (!all_uses_are_call || must_tail_call || uses_are_indirect_call ||
          F.isInterposable() || F.hasAddressTaken()) {
        fprintf(stderr, "IPRA: Function: %s[%s]", FNameCStr, CUNameStr.c_str());
        if (!all_uses_are_call)
          fprintf(stderr, " AllUsesAreNotCall: 1");
        if (must_tail_call)
          fprintf(stderr, " MustTailCall: 1");
        if (uses_are_indirect_call)
          fprintf(stderr, " UsesAreIndirectCall: 1");
        if (F.isInterposable())
          fprintf(stderr, " IsInterposable: 1");
        if (F.hasAddressTaken())
          fprintf(stderr, " HasAddressTaken: 1");
        fprintf(stderr, "\n");
      }
    }
    return PreservedAnalyses::all();
  }

  bool Changed = false;
  for (Function &F : M.functions()) {
    // if (F.getName() == "_ZNSt3__u12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEmc") {
    //   fprintf(stderr, "IPRA: looking at my prereserve none function.\n");
    //   dbg = true;
    // }
    if (FunctionSymsMap.contains(F.getName())) {
      if (F.hasAddressTaken()) {
        // dbgs() << "IPRA: Still Has Address Taken:" << F.getName() << "\n";
        fprintf(stderr, "IPRA: Still HasAddressTaken: %s\n",
                F.getName().str().c_str());
        continue;
      }

      bool doable = true;
      for (User *U : F.users()) {
        //  if (isa<BlockAddress>(U) || !isa<CallInst>(U)) {
        if (!isa<CallInst>(U)) {
          doable = false;
          break;
        }
      }
      if (!doable) {
        fprintf(stderr, "IPRA: skipped %s\n", F.getName().str().c_str());
        continue;
      }

      bool must_tail_call = false;
      std::vector<CallInst *> Calls;
      if (!F.isDeclaration()) {
        for (BasicBlock &B : F) {
          for (Instruction &I : B) {
            if (isa<CallInst>(I)) {
              CallInst *ci = cast<CallInst>(&I);
              if (ci->isMustTailCall()) {
                must_tail_call = true;
                break;
              }
              Calls.push_back(ci);
            }
          }
          if (must_tail_call)
            break;
        }
      }
      // Tailcall check 2.
      bool all_uses_are_call = true;
      if (!must_tail_call) {
        for (User *U : F.users()) {
          if (isa<CallInst>(U)) {
            CallInst *ci = cast<CallInst>(U);
            if (ci->isMustTailCall()) {
              must_tail_call = true;
              break;
            }
            Calls.push_back(ci);
          } else {
            all_uses_are_call = false;
            break;
          }
        }
      }
      if (!all_uses_are_call) {
        fprintf(stderr, "IPRA: Still AllUsesAreNotCall: %s\n",
                F.getName().str().c_str());
        continue;
      }
      if (must_tail_call) {
        fprintf(stderr, "IPRA: Still MustTailCall: %s\n",
                F.getName().str().c_str());
        continue;
      }

      // Mark all calls as No tail call.
      for (CallInst *CI : Calls) {
        // const Function *F = CI->getCalledFunction();
        // if (F)
        //   fprintf(stderr, "IPRA(dbg): set %s to not tail call\n",
        //           F->getName().str().c_str());
        // CI->setTailCall(false);
        CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
      }

      F.setCallingConv(CallingConv::PreserveNone);
      fprintf(stderr,
              "IPRA: applied PreserveNone to \"%s\" (is_declaration=%d, "
              "module=%s)\n",
              F.getName().str().c_str(), F.isDeclaration(),
              M.getName().str().c_str());
      for (User *U : F.users()) {
        if (!isa<CallInst>(U)) {
          fprintf(stderr, "ERROR: use is not a call, aborted.\n");
          exit(1);
        }
        CallInst *CI = cast<CallInst>(U);
        // CallBase *CI = cast<CallBase>(U);
        // CI->setTailCall(false);
        CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
        fprintf(stderr,
                "IPRA: applied no tail call to CI \"%s\" (called by %s)\n",
                CI->getCalledFunction()->getName().str().c_str(),
                CI->getCaller()->getName().str().c_str());
        CI->setCallingConv(CallingConv::PreserveNone);
        fprintf(stderr, "IPRA: applied PreserveNone to \"%s\" (called by %s)\n",
                CI->getCalledFunction()->getName().str().c_str(),
                CI->getCaller()->getName().str().c_str());
      }
      // fprintf(stderr, "IPRA: %s users >>>\n", F.getName().str().c_str());
      // for (llvm::User *const U : F.users()) {
      //   U->dump();
      // }
      // fprintf(stderr, "IPRA: <<< \n");
      Changed = true;
    }
  }
  if (Changed)
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

