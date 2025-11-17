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
#include "llvm/Transforms/Utils/Cloning.h" // <-- Added for CloneFunction

// // For online analysis in bottom up order
// #include "llvm/Analysis/CallGraph.h"
// #include "llvm/IR/CallGraphSCCPass.h"

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

  // A set to store the names of functions we modify.
  std::set<std::string> PreserveNoneFunctions;

  // --- MODIFICATION: Collect functions first to avoid iterator invalidation ---
  // when cloning and adding new functions to the module.
  SmallVector<Function*, 64> FunctionsToProcess;
  for (Function &F : M) {
      if (Candidates.find(F.getName().str()) != Candidates.end()) {
          FunctionsToProcess.push_back(&F);
      }
  }

  // Now, iterate over the collected list
  for (Function *FPtr : FunctionsToProcess) {
    Function &F = *FPtr;

    // --- Fork behavior based on hasAddressTaken ---
    if (F.hasAddressTaken()) {
        
        // === 1. CLONE THE FUNCTION ===
        ValueToValueMapTy VMap; 
        Function *F_clone = CloneFunction(&F, VMap);

        // === 2. MODIFY THE CLONE ===
        F_clone->setName(F.getName() + ".preserve_none");
        F_clone->setCallingConv(CallingConv::PreserveNone);
        F_clone->setLinkage(GlobalValue::InternalLinkage); // Make internal

        // Also disable tail calls *within* the clone, copying original logic
        if (!F_clone->isDeclaration()) {
            for (BasicBlock &B : *F_clone) {
                for (Instruction &I : B) {
                    if (auto *CI = dyn_cast<CallInst>(&I)) {
                        CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
                    }
                }
            }
        }

        // Add the new clone to the module
        F.getParent()->getFunctionList().push_back(F_clone);

        PreserveNoneFunctions.insert(F.getName().str());
        Changed = true;
        WithColor::note(errs()) << "[PreserveNone] Cloned " << F.getName() 
                                << " to " << F_clone->getName() << " for AddressTaken\n";

        // === 3. MODIFY THE ORIGINAL (F) - CREATE STUB ===
        // F keeps its original name and *standard* calling convention
        
        F.deleteBody(); // Remove all old basic blocks
        BasicBlock *StubBB = BasicBlock::Create(F.getContext(), "stub_entry", &F);
        
        // Gather arguments to pass to the clone
        SmallVector<Value*, 16> Args;
        for (auto &Arg : F.args()) {
            Args.push_back(&Arg);
        }

        // Create the call to the clone
        CallInst *CloneCall = CallInst::Create(F_clone->getFunctionType(), F_clone, Args, "", StubBB);
        CloneCall->setCallingConv(CallingConv::PreserveNone); // Call clone with new CC
        CloneCall->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);

        // Create the return instruction
        if (F.getReturnType()->isVoidTy()) {
            ReturnInst::Create(F.getContext(), StubBB);
        } else {
            ReturnInst::Create(F.getContext(), CloneCall, StubBB);
        }

        // === 4. UPDATE USERS OF THE ORIGINAL (F) ===
        // Must copy user list before modifying it
        SmallVector<User*, 16> Users(F.users());
        for (User *U : Users) {
            if (auto *CB = dyn_cast<CallBase>(U)) {
                // This is a direct call site. Retarget it to the clone.
                CB->setCalledFunction(F_clone);
                CB->setCallingConv(CallingConv::PreserveNone);
                if (auto *CI = dyn_cast<CallInst>(CB)) {
                    CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
                }
                WithColor::note(errs()) << "[PreserveNone] Retagged direct callsite in: "
                                        << CB->getFunction()->getName() << "\n";
            } 
            // else: This is an address-taken use (e.g., store, constant).
            // We *leave it alone*. It will now correctly point to
            // the stub (F), which handles the ABI.
        }

    } else {
        // === THIS IS THE ORIGINAL "SIMPLE" LOGIC (for !hasAddressTaken) ===
        
        // 1. Set the calling convention for the function itself.
        if (F.getCallingConv() != CallingConv::PreserveNone) {
            F.setCallingConv(CallingConv::PreserveNone);
            Changed = true;
            WithColor::note(errs()) << "[PreserveNone] Retagged function: " << F.getName() << "\n";
            PreserveNoneFunctions.insert(F.getName().str());
        }

        // 2. Disable tail calls *within* the function itself.
        if (!F.isDeclaration()) {
            for (BasicBlock &B : F) {
                for (Instruction &I : B) {
                    if (auto *CI = dyn_cast<CallInst>(&I)) {
                        CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
                        Changed = true;
                    }
                }
            }
        }

        // 3. Modify the call sites that call this function.
        // (Since hasAddressTaken is false, all users are CallBase)
        for (User *U : F.users()) {
            auto *CB = cast<CallBase>(U);

            if (auto *CI = dyn_cast<CallInst>(CB)) {
                CI->setTailCallKind(CallInst::TailCallKind::TCK_NoTail);
                Changed = true;
            }

            if (CB->getCallingConv() != CallingConv::PreserveNone) {
                CB->setCallingConv(CallingConv::PreserveNone);
                Changed = true;
                WithColor::note(errs()) << "[PreserveNone] Retagged callsite in: "
                                        << CB->getFunction()->getName() << "\n";
            }
        }
    }
  } // --- End of loop over FunctionsToProcess ---

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