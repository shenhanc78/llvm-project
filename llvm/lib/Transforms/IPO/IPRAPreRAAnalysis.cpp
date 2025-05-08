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

#include <cstdio>
#include <iomanip>
#include <iostream>
#include <list>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <system_error>  // NOLINT
#include <vector>

#include "llvm/Transforms/IPO/IPRAPreRAAnalysis.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

// #include "llvm/IR/BasicBlock.h"
// #include "llvm/IR/DebugInfoMetadata.h"
// #include "llvm/IR/Function.h"
// #include "llvm/IR/GlobalAlias.h"
// #include "llvm/IR/GlobalObject.h"
// #include "llvm/IR/GlobalValue.h"
// #include "llvm/IR/Instructions.h"
// #include "llvm/IR/SymbolTableListTraits.h"
// #include "llvm/Pass.h"

// #include "llvm/Support/Casting.h"
// #include "llvm/Support/CommandLine.h"
// #include "llvm/Support/Debug.h"

// #include "llvm/Target/TargetMachine.h"

using namespace ::llvm;  // NOLINT

#define DEBUG_TYPE "iprapreraanalysis"

static cl::opt<std::string>
    IPRAPreRAFunctionSymsFile("ipra-prera-function-syms-file",
                              cl::desc("File containing the symbo list"),
                              cl::init(""), cl::Hidden);

static cl::opt<std::string> IPRAPreRAAnalysisOutputDir(
    "ipra-prera-analysis-output-dir",
    cl::desc("Directory to store the analysis output"),
    cl::init("/tmp/ipra_prera_analysis"), cl::Hidden);

namespace {
  std::uniform_int_distribution<> unified_distribution(0, 255);

std::string generateRandomFilename(const std::string &prefix = "temp_",
                                   const std::string &extension = ".txt") {
  std::random_device rd;
  std::mt19937 gen(rd());

  std::stringstream ss;
  ss << prefix;
  for (int i = 0; i < 32; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << unified_distribution(gen);
  }
  ss << extension;
  return ss.str();
}

bool ensureDirectoryExists(const std::string &directoryPath) {
  llvm::sys::fs::file_status status;

  // Check if the directory exists
  if (!llvm::sys::fs::status(directoryPath,
                             status)) {  // Negate to check for success.
    if (llvm::sys::fs::exists(status) && llvm::sys::fs::is_directory(status)) {
      return true;  // Directory already exists
    }
  }

  // Directory doesn't exist, create it
  std::error_code ec = llvm::sys::fs::create_directories(directoryPath);
  if (ec) {
    llvm::errs() << "Error creating directory " << directoryPath << ": "
                 << ec.message() << "\n";
    return false;  // Failed to create directory
  }
  return true;  // Directory created successfully
}
}  // namespace

// First dry run the symbol list to get all symbols that have a definition and
// then use that pruned list.
static cl::opt<bool>
    IPRADryRun("ipra-dry-run", cl::desc("Dry run to get valid function names"),
               cl::init(false), cl::Hidden);

static const std::string embedded_syms[] = {  // NOLINT
  #include "llvm/Transforms/IPO/embedded_syms.h"
};

static const std::list<std::string> tailcall_chains[] = {
  #include "llvm/Transforms/IPO/embedded_tcs.h"
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
  return count;
}

// Returns true if the function is part of the tail call chain.
bool ProcessTailCallChain(const StringMap<unsigned> &FunctionSymsMap,
                          Function &F,
                          raw_ostream &OS) {
  std::set<std::string> chain_func_set = {};
  for (const std::list<std::string> &chain : tailcall_chains)
    for (const std::string& func_name : chain)
      chain_func_set.insert(func_name);

  bool found = false;
  size_t total_chains =
      sizeof(tailcall_chains) / sizeof(std::list<std::string>);
  OS << "IPRA: Total tailcall chains: " << total_chains << "\n";
  for (size_t chain_iter = 0; !found && chain_iter < total_chains; ++chain_iter)
    for (auto chain_func_iter = tailcall_chains[chain_iter].begin();
         !found && (chain_func_iter != tailcall_chains[chain_iter].end());
         ++chain_func_iter)
      if (F.getName() == *chain_func_iter)
        found = true;

  if (!found)
    return false;

  for (User *U : F.users())
    if (!isa<CallInst>(U))
      llvm::report_fatal_error("Unexpected: not all of function users "
                               "are call instructions: " +
                               F.getName());

  // 1. Set the calling conv of F to preserve none.
  F.setCallingConv(CallingConv::PreserveNone);
  OS << "IPRA: set " << F.getName() << " to preserve none (tailcall)\n";

  // 2. Make sure all callers of F are not tail call except the caller is
  // already a preserve none function or when the caller is in the tail call
  // chain.
  for (User *U : F.users()) {
    CallInst *CI = cast<CallInst>(U);
    // All instructions to call F are preserve none.
    CI->setCallingConv(CallingConv::PreserveNone);

    Function *Caller = CI->getCaller();
    if (FunctionSymsMap.contains(Caller->getName()) ||
        chain_func_set.find(std::string(Caller->getName())) !=
            chain_func_set.end()) {
      OS << "IPRA: both caller and callee are preserve none, do not change "
            "tail call kind: "
         << Caller->getName() << "->" << F.getName() << "\n";
    } else {
      CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
      OS << "IPRA: set call: " << Caller->getName() << "->" << F.getName()
             << " to no tail call\n";
    }
  }

  // 3. Make sure all callees of F are not tail call except when the callee is
  // in the tail call chain or when the callee is a preserve none function.
  if (F.isDeclaration())
    return true;

  for (BasicBlock &B : F) {
    for (Instruction &I : B) {
      if (!isa<CallInst>(I))
        continue;

      CallInst *CI = cast<CallInst>(&I);
      if (!CI)
        continue;
      Function *Callee = CI->getCalledFunction();
      if (!Callee) {
        CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
        continue;
      }
      if (FunctionSymsMap.contains(Callee->getName()) ||
          chain_func_set.find(std::string(Callee->getName())) !=
              chain_func_set.end()) {
        OS << "IPRA: both caller and callee are preserve none, do not change "
              "tail call kind: "
           << F.getName() << "->" << Callee->getName() << "\n";
      } else {
        CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
        OS << "IPRA: set call: " << F.getName() << "->" << Callee->getName()
           << " to no tail call\n";
      }
    }
  }
  return true;
}

PreservedAnalyses IPRAPreRAAnalysisPass::run(Module &M,
                                             ModuleAnalysisManager &AM) {
  StringMap<unsigned> FunctionSymsMap;

  unsigned int MapEleCount = 0;
  if (IPRAPreRAFunctionSymsFile != "") {
    MapEleCount = parseSymbolsFile(FunctionSymsMap);
    // dbgs() << "MapEleCount : " << MapEleCount << "\n";
    // fprintf(stderr, "IPRA: MapEleCount: %d\n", MapEleCount);
  }
  if (!IPRADryRun && MapEleCount == 0) return PreservedAnalyses::all();

  // The Dry Run must explicitly print out address taken functions so that
  // we can eliminate them.  Comdats might be address taken in one module and
  // not in the other module.
  if (IPRADryRun) {
    if (!ensureDirectoryExists(IPRAPreRAAnalysisOutputDir))
      llvm::report_fatal_error(llvm::StringRef("ensureDirectoryExists failed"));
    llvm::SmallString<128> OutputPrefix =
        llvm::StringRef(IPRAPreRAAnalysisOutputDir);
    llvm::sys::path::append(OutputPrefix, "ipra_prera_analysis_");
    std::string OutputFilename =
        generateRandomFilename(std::string(OutputPrefix));
    std::error_code EC;
    llvm::raw_ostream *OS = new llvm::raw_fd_ostream(
        OutputFilename, EC, llvm::sys::fs::CreationDisposition::CD_CreateNew,
        llvm::sys::fs::FileAccess::FA_Write, llvm::sys::fs::OpenFlags::OF_Text);
    if (EC) {
      llvm::report_fatal_error(llvm::StringRef("Could not open file: ") +
                               EC.message());
    }

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
        (*OS) << "IPRA: Function: " << FNameCStr << "[" << CUNameStr << "]";
        if (!all_uses_are_call)
          (*OS) << " AllUsesAreNotCall: 1";
        if (must_tail_call)
          (*OS) << " MustTailCall: 1";
        if (uses_are_indirect_call)
          (*OS) << " UsesAreIndirectCall: 1";
        if (F.isInterposable())
          (*OS) << " IsInterposable: 1";
        if (F.hasAddressTaken())
          (*OS) << " HasAddressTaken: 1";
        (*OS) << "\n";
      }
    }
    if (OS) {
      OS->flush();
      delete OS;
      OS = nullptr;
    }
    return PreservedAnalyses::all();
  }  // end of IPRADryRun

  bool Changed = false;

  // const std::string tc_head = "sk_forced_mem_schedule";
  // const std::string tc_tail = "mem_cgroup_charge_skmem";

  for (Function &F : M.functions()) {
    // if (ProcessTailCallChain(FunctionSymsMap, F, llvm::errs())) {
    //   Changed = true;
    //   continue;
    // }

    ////
    if (FunctionSymsMap.contains(F.getName())) {
      if (F.hasAddressTaken()) {
        // dbgs() << "IPRA: Still Has Address Taken:" << F.getName() <<
        // "\n";
        fprintf(stderr, "IPRA: Still HasAddressTaken: %s\n",
                F.getName().str().c_str());
        continue;
      }

      bool doable = true;
      for (User *U : F.users()) {
        if (isa<BlockAddress>(U) || !isa<CallInst>(U)) {
          // if (!isa<CallInst>(U)) {
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
      // ipra2:
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
          llvm::report_fatal_error(llvm::StringRef("use is not a call"));
        }
        CallInst *CI = cast<CallInst>(U);
        // CI->setTailCall(false);

        // ipra2:
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
