#include "llvm/Transforms/IPO/PreserveNonePass.h"

#include <cstdio>
#include <iomanip>
#include <iostream>
#include <list>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstrTypes.h"
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
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// ---------- Flags (available to opt/clang when LLVMIpo is linked) ----------
static cl::OptionCategory PreserveNoneCat("PreserveNonePass Options");

static cl::opt<bool> EnablePreserveNone(
    "preserve-none-enable",
    cl::desc("Enable the preserve_none optimization pass"),
    cl::init(false), cl::cat(PreserveNoneCat));

static cl::opt<std::string> PreserveNoneJsonPath(
    "preserve-none-json",
    cl::desc("Path to JSON file containing {\"functions\": {\"name\": score, ...}}"),
    cl::init(""), cl::cat(PreserveNoneCat));

static cl::opt<std::string> PreserveNoneRecordPath(
    "preserve-none-record",
    cl::desc("Path to output a record of functions that are being assigned preserved_nonecc"),
    cl::init("./pn_functions.txt"), cl::cat(PreserveNoneCat));

// ---------- JSON Parsing ----------
// Parse {"functions": {"name": number, ...}} JSON file.
// TODO: this may be a ttxtemporary solution for storing profile data.
// In the long term we may want to integrate with PGO infrastructure.
static std::set<std::string> loadCandidateJSON(StringRef Path) {
  std::set<std::string> C;

  if (Path.empty()) {
    WithColor::warning(errs()) << "[PreserveNone] No JSON path provided; no functions selected.\n";
    return C;
  }

  auto BufOrErr = MemoryBuffer::getFile(Path);
  if (!BufOrErr) {
    WithColor::warning(errs()) << "[PreserveNone] Failed to read JSON: " << Path << "\n";
    return C;
  }

  Expected<json::Value> Parsed = json::parse(BufOrErr.get()->getBuffer());
  if (!Parsed) {
    WithColor::warning(errs()) << "[PreserveNone] Invalid JSON: " << Path << "\n";
    consumeError(Parsed.takeError());
    return C;
  }

  auto *Obj = Parsed->getAsObject();
  if (!Obj) {
    WithColor::warning(errs()) << "[PreserveNone] Root must be an object\n";
    return C;
  }

  auto *Fns = Obj->getObject("functions");
  if (!Fns) {
    WithColor::warning(errs()) << "[PreserveNone] Missing \"functions\" object\n";
    return C;
  }

  for (auto &KV : *Fns) {
    std::string func_name = KV.first.str();
    C.insert(func_name);
  }
  return C;
}

// ---------- Helpers ----------
static bool isDirectUserOf(const CallBase &CB, const Function &F) {
  const Value *Callee = CB.getCalledOperand();
  Callee = Callee->stripPointerCasts();
  return Callee == &F;
}

static bool isSafeForPreserveNone(const Function &F) {
    // --- Initial simple checks ---
    if (F.isIntrinsic() || F.isVarArg() || F.isInterposable() || 
        F.hasAddressTaken() || F.getCallingConv() != CallingConv::C || F.getName() == "main") {
        return false;
    }

    // --- Check if the function ITSELF contains a must-tail call ---
    if (!F.isDeclaration()) {
        for (const BasicBlock &B : F) {
            for (const Instruction &I : B) {
                if (const auto *CI = dyn_cast<CallInst>(&I)) {
                    if (CI->isMustTailCall()) {
                      WithColor::warning(errs()) << "[PreserveNone] Reject: " << F.getName() << " contains a must-tail call.\n";
                      return false;
                    }
                    // To check tail call, must check isDeclaration function F as well, but need to modify current analysis pass
                    // if (CI->isTailCall()) {
                    //   WithColor::warning(errs()) << "[PreserveNone] Reject: " << F.getName() << " contains a tail call.\n";
                    //   return false;
                    // }
                }
            }
        }
    }

    // --- Check all USERS of the function for unsafe patterns ---
    for (const User *U : F.users()) {
        // User must not be a block address and must be a call instruction.
        if (isa<BlockAddress>(U) || !isa<CallInst>(U)) {
          WithColor::warning(errs()) << "[PreserveNone] Reject: " << F.getName() << " has a user that is not a CallBase.\n";
          return false;
        }

        const auto *CB = cast<CallBase>(U);

        // Must be a direct call.
        if (!isDirectUserOf(*CB, F)) {
          WithColor::warning(errs()) << "[PreserveNone] Reject: " << F.getName() << " has an indirect call user.\n";
          return false;
        }

        // The call site itself must not be a must-tail call.
        if (CB->isMustTailCall()) {
          WithColor::warning(errs()) << "[PreserveNone] Reject: " << F.getName() << " is the target of a must-tail call.\n";
          return false;
        }

        // if (CB->isTailCall()) {
        //   WithColor::warning(errs()) << "[PreserveNone] Reject: " << F.getName() << " is the target of a tail call.\n";
        //   return false;
        // }
    }

    return true;
}

// ---------- Pass ----------
PreservedAnalyses PreserveNonePass::run(Module &M, ModuleAnalysisManager &MAM) {
  if (!EnablePreserveNone){
    return PreservedAnalyses::all(); // hard gate
  }

  std::set<std::string> Candidates = loadCandidateJSON(PreserveNoneJsonPath);
  if (Candidates.empty()) {
    WithColor::warning(errs()) << "[PreserveNone] Candidate set empty; nothing to do.\n";
    return PreservedAnalyses::all();
  }

  bool Changed = false;
  SmallVector<Function*, 16> Targets;

  // A set to store the names of functions we modify.
  std::set<std::string> PreserveNoneFunctions;

  // Intersect JSON list with module contents + new safety filters.
  for (Function &F : M) {
    if (Candidates.find(F.getName().str()) != Candidates.end() && isSafeForPreserveNone(F)) {
        Targets.push_back(&F);
    }
  }

  if (Targets.empty()) {
    WithColor::note(errs()) << "[PreserveNone] No eligible functions after filtering.\n";
    return PreservedAnalyses::all();
  }

  // Apply the transformation.
  for (Function *F : Targets) {
    // 1. Disable tail calls on any calls *within* the function itself.
    if (!F->isDeclaration()) {
      for (BasicBlock &B : *F) {
        for (Instruction &I : B) {
          if (auto *CI = dyn_cast<CallInst>(&I)) {
            if (CI->isTailCall()) {
              CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
              Changed = true;
            }
          }
        }
      }
    }

    // 2. Modify the call sites that call this function.
    for (User *U : F->users()) {
      auto *CB = cast<CallBase>(U);

      // Disable tail calls at the call site.
      if (auto *CI = dyn_cast<CallInst>(CB)) {
        if (CI->isTailCall()) {
           CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
           Changed = true;
        }
      }

      // Set the calling convention for the call site.
      if (CB->getCallingConv() != CallingConv::PreserveNone) {
        CB->setCallingConv(CallingConv::PreserveNone);
        Changed = true;
        WithColor::note(errs()) << "[PreserveNone] Retagged callsite in: "
                                << CB->getFunction()->getName() << "\n";
      }
    }

    // 3. Set the calling convention for the function itself.
    if (F->getCallingConv() != CallingConv::PreserveNone) {
      F->setCallingConv(CallingConv::PreserveNone);
      Changed = true;
      WithColor::note(errs()) << "[PreserveNone] Retagged function: " << F->getName() << "\n";
      // Add the function's name to our set.
      PreserveNoneFunctions.insert(F->getName().str());
    }
  }

  // Write the collected unique function names to the output file.
  if (Changed && !PreserveNoneRecordPath.empty() && !PreserveNoneFunctions.empty()) {
    std::error_code EC;
    raw_fd_ostream OutputFile(PreserveNoneRecordPath, EC, sys::fs::OF_Text | sys::fs::OF_Append);
    if (EC) {
        WithColor::warning(errs()) << "[PreserveNone] Could not open record output file: "
                                   << PreserveNoneRecordPath << " - " << EC.message() << "\n";
    } else {
        for (const auto &FuncName : PreserveNoneFunctions) {
            OutputFile << FuncName << "\n";
        }
        WithColor::note(errs()) << "[PreserveNone] Wrote " << PreserveNoneFunctions.size()
                                << " function names to " << PreserveNoneRecordPath << "\n";
    }
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
