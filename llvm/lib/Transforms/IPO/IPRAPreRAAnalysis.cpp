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
#include <random>
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

  //   if (F.getName() == tc_head) {
  //     // This is tail call header, its caller must not use tailcall unless
  //     // caller is preserve none.
  //     bool do_not_apply_pn = false;
  //     for (User *U : F.users()) {
  //       if (!isa<CallInst>(U)) {
  //         fprintf(
  //             stderr,
  //             "IPRA: skipped tail call because of none call instruction: %s\n",
  //             F.getName().str().c_str());
  //         do_not_apply_pn = true;
  //         break;
  //       }
  //     }
  //     if (do_not_apply_pn)
  //       continue;

  //     F.setCallingConv(CallingConv::PreserveNone);
  //     fprintf(stderr, "IPRA: set %s to preserve none\n", tc_head.c_str());

  //     for (User *U : F.users()) {
  //       // We already know "U" must be a call instruction.
  //       CallInst *CI = cast<CallInst>(U);
  //       CI->setCallingConv(CallingConv::PreserveNone);

  //       Function *Caller = CI->getCaller();
  //       if (!FunctionSymsMap.contains(Caller->getName())) {
  //         CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
  //         fprintf(stderr, "IPRA: set call: %s->%s to no tail call\n",
  //                 std::string(CI->getCaller()->getName()).c_str(),
  //                 tc_head.c_str());
  //       } else {
  //         // Caller is also preserve none, do not change tail call or not
  //         fprintf(stderr,
  //                 "IPRA: call: %s->%s is PN to PN, do not change tail call\n",
  //                 std::string(CI->getCaller()->getName()).c_str(),
  //                 tc_head.c_str());
  //       }
  //     }

  //     if (!F.isDeclaration()) {
  //       for (BasicBlock &B : F) {
  //         for (Instruction &I : B) {
  //           if (isa<CallInst>(I)) {
  //             CallInst *CI = cast<CallInst>(&I);
  //             if (CI) {
  //               Function *Callee = CI->getCalledFunction();
  //               if (!Callee) {
  //                 CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
  //                 continue;
  //               }
  //               if (Callee->getName() == tc_tail) {
  //                 continue;
  //               }
  //               if (!FunctionSymsMap.contains(Callee->getName())) {
  //                 CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
  //                 fprintf(stderr, "PIRA: set call: %s->%s to no tail call\n",
  //                         std::string(CI->getCaller()->getName()).c_str(),
  //                         std::string(Callee->getName()).c_str());
  //               } else {
  //                 // this callee is also preserve-none, do not change
  //                 // tail call or not.
  //                 fprintf(stderr,
  //                         "IPRA: call: %s->%s is PN to PN, do not change tail "
  //                         "call\n",
  //                         std::string(CI->getCaller()->getName()).c_str(),
  //                         std::string(Callee->getName()).c_str());
  //               }
  //             }
  //           }
  //         }
  //       }
  //     }
  //     continue;
  //   }

  //   if (F.getName() == tc_tail) {
  //     bool do_not_apply_pn = false;
  //     for (User *U : F.users()) {
  //       if (!isa<CallInst>(U)) {
  //         fprintf(
  //             stderr,
  //             "IPRA: skipped tail call because of none call instruction: %s\n",
  //             F.getName().str().c_str());
  //         do_not_apply_pn = true;
  //         break;
  //       }
  //     }
  //     if (do_not_apply_pn)
  //       continue;

  //     // This is tail call end
  //     F.setCallingConv(CallingConv::PreserveNone);
  //     fprintf(stderr, "IPRA: set %s to preserve none\n", tc_tail.c_str());

  //     for (User *U : F.users()) {
  //       // We already know "U" must be a call instruction.
  //       CallInst *CI = cast<CallInst>(U);
  //       CI->setCallingConv(CallingConv::PreserveNone);

  // 	llvm::StringRef CallerName = CI->getCaller()->getName();
  //       if (CallerName == tc_head || FunctionSymsMap.contains(CallerName)) {
  //         fprintf(stderr,
  //                 "IPRA: call: %s->%s is PN to PN, do not change tail call\n",
  //                 tc_head.c_str(), tc_tail.c_str());
  //         // CI->setTailCallKind(CallInst::TailCallKind::TCK_MustTail);
  //       } else {
  //         CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
  //         fprintf(stderr,
  //                 "IPRA: set call: "
  //                 "%s->%s to no tail call\n",
  //                 CallerName.str().c_str(), tc_tail.c_str());
  //       }
  //     }

  //     // The function on the tail call chain, change all its
  //     // none-preserve-none callee's call to no tail call.
  //     if (!F.isDeclaration()) {
  //       for (BasicBlock &B : F) {
  //         for (Instruction &I : B) {
  //           if (isa<CallInst>(I)) {
  //             CallInst *CI = cast<CallInst>(&I);
  //             if (CI) {
  //               Function *Callee = CI->getCalledFunction();
  //               if (!Callee) {
  //                 CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
  //               } else if (!FunctionSymsMap.contains(Callee->getName())) {
  //                 CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
  //                 fprintf(stderr, "IPRA: set call: %s->%s to no tail call\n",
  //                         std::string(CI->getCaller()->getName()).c_str(),
  //                         std::string(Callee->getName()).c_str());
  //               } else {
  //                 // this callee is also preserve-none, do not change
  //                 // tail call or not.
  //                 fprintf(stderr,
  //                         "IPRA: call: %s->%s is PN to PN, do not change tail "
  //                         "call\n",
  //                         std::string(CI->getCaller()->getName()).c_str(),
  //                         std::string(Callee->getName()).c_str());
  //               }
  //             }
  //           }
  //         }
  //       }
  //     }

  //     continue;
  //   } // end of processing tail call pair.

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
