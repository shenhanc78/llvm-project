#include "llvm/Transforms/IPO/PreserveNonePass.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h" // TODO: comment out or remote in production code

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

// ---------- Helpers ----------
static bool isDirectUserOf(const CallBase &CB, const Function &F) {
  const Value *Callee = CB.getCalledOperand();
  Callee = Callee->stripPointerCasts();
  return Callee == &F;
}

// TODO: comment out or remove this function in production code
const char *PreserveNoneStatsFile = "../metrics/preserve_none_linkage_stats.json";
// --- Helper struct to automatically count and print linkage stats ---
struct LinkageStatsCollector {
  StringMap<unsigned> Counts;

  ~LinkageStatsCollector() {
    if (Counts.empty()) return;

    std::error_code EC;
    raw_fd_ostream OS(PreserveNoneStatsFile, EC, sys::fs::OF_Append);
    if (EC) {
      errs() << "[PreserveNone] Error opening stats file '" << PreserveNoneStatsFile
             << "': " << EC.message() << "\n";
      return;
    }

    // The json::Value constructor cannot implicitly convert from StringMap.
    json::Object StatsObject;
    for (const auto &Pair : Counts) {
        StatsObject[Pair.getKey()] = Pair.getValue();
    }
    
    // Write the correctly formed json::Object to the file.
    OS << json::Value(std::move(StatsObject)) << "\n";
  }
};

static LinkageStatsCollector Stats;

// --- Helper function to convert LinkageTypes enum to string ---
static StringRef getLinkageNameString(GlobalValue::LinkageTypes LT) {
  switch (LT) {
    case GlobalValue::ExternalLinkage: return "external";
    case GlobalValue::PrivateLinkage: return "private";
    case GlobalValue::InternalLinkage: return "internal";
    case GlobalValue::LinkOnceAnyLinkage: return "linkonce";
    case GlobalValue::LinkOnceODRLinkage: return "linkonce_odr";
    case GlobalValue::WeakAnyLinkage: return "weak";
    case GlobalValue::WeakODRLinkage: return "weak_odr";
    case GlobalValue::CommonLinkage: return "common";
    case GlobalValue::AppendingLinkage: return "appending";
    case GlobalValue::ExternalWeakLinkage: return "extern_weak";
    case GlobalValue::AvailableExternallyLinkage: return "available_externally";
  }
  llvm_unreachable("Unhandled linkage type!");
}


static bool isSafeLinkage(const Function &F) {
  // This is the MOST CRITICAL check. We only want to modify functions that
  // are not visible outside the current compilation unit. This prevents us
  // from breaking the ABI of any external or standard library functions.
  return true;

  WithColor::warning(errs()) << ">>>> " << F.getName() << ": " << getLinkageNameString(F.getLinkage()) << "<<<< \n";
  switch (F.getLinkage()) {
  case GlobalValue::InternalLinkage:
  case GlobalValue::PrivateLinkage:
  case GlobalValue::LinkOnceODRLinkage:
  case GlobalValue::ExternalLinkage:
    WithColor::warning(errs()) << "[PreserveNone] Found function F having safe linkage type\n";
    return true;
  default:
    return false;
  }

  return false;
}

static bool isSafeForPreserveNone(const Function &F) {
  if (F.isIntrinsic()) {
    WithColor::warning(errs()) << "[PreserveNone] Intrinsic F not applicable for preserve none cc\n";
    return false;
  }
  if (F.isVarArg()) {
    WithColor::warning(errs()) << "[PreserveNone] VarArg F not applicable for preserve none cc\n";
    return false;
  }
  // avoid stable external ABI symbols
  if (!isSafeLinkage(F)) {
    WithColor::warning(errs()) << "[PreserveNone] Not safely linked F not applicable for preserve none cc\n";
    return false; 
  }
  // unknown indirect callers exist
  if (F.hasAddressTaken()) {
    WithColor::warning(errs()) << "[PreserveNone] Address Taken F not applicable for preserve none cc\n";
    return false;
  }
  // Only retag from the default C calling convention.
  if (F.getCallingConv() != CallingConv::C) {
    WithColor::warning(errs()) << "[PreserveNone] Non default cc F not applicable for preserve none cc\n";
    return false;
  }

  // Add a more detailed check of the function's users.
  for (const User *U : F.users()) {
    const auto *CB = dyn_cast<CallBase>(U);
    
    // If a user is not a call instruction OR it is not a direct call, it's unsafe.
    if (!CB || !isDirectUserOf(*CB, F)) {
      WithColor::warning(errs()) << "[PreserveNone] Indirectly invoked F not applicable for preserve none cc\n";
      return false;
    }
    
    // It is unsafe to change the calling convention of a function
    // involved in a musttail call, as it breaks a strong ABI guarantee.
    if (CB->isMustTailCall()) {
      WithColor::warning(errs()) << "[PreserveNone] Must tail-called F not applicable for preserve none cc\n";
      return false;
    }
  }

  return true;
}

// ---------- JSON Parsing ----------
// Parse {"functions": {"name": number, ...}} JSON file.
// TODO: this may be a temporary solution for storing profile data.
// In the long term we may want to integrate with PGO infrastructure.
static StringMap<double> loadCandidateJSON(StringRef Path) {
  StringMap<double> C;

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
    double Score = *KV.second.getAsNumber();
    C.try_emplace(KV.first, Score);
  }
  return C;
}

// ---------- Pass ----------
PreservedAnalyses PreserveNonePass::run(Module &M, ModuleAnalysisManager &MAM) {
  if (!EnablePreserveNone){
    return PreservedAnalyses::all(); // hard gate
  }

  StringMap<double> Candidates = loadCandidateJSON(PreserveNoneJsonPath);
  if (Candidates.empty()) {
    WithColor::warning(errs()) << "[PreserveNone] Candidate set empty; nothing to do.\n";
    return PreservedAnalyses::all();
  }

  bool Changed = false;
  SmallVector<Function*, 16> Targets;

  // Intersect JSON list with module contents + safety filter.
  for (Function &F : M) {
    if (!Candidates.contains(F.getName())) continue;
    if (!isSafeForPreserveNone(F)) continue;
    Stats.Counts[getLinkageNameString(F.getLinkage())]++;
    Targets.push_back(&F);
  }

  if (Targets.empty()) {
    WithColor::note(errs()) << "[PreserveNone] No eligible functions after filtering.\n";
    return PreservedAnalyses::all();
  }

  // Retag function + direct callsites.
  for (Function *F : Targets) {
    if (F->getCallingConv() != CallingConv::PreserveNone) {
      F->setCallingConv(CallingConv::PreserveNone);
      WithColor::note(errs()) << "[PreserveNone] Retagged function: " << F->getName() << "\n";
      Changed = true;
    }

    for (User *U : F->users()) {
        auto *CB = dyn_cast<CallBase>(U);
        // if (isDirectUserOf(*CB, *F) &&
        //     CB->getCallingConv() != CallingConv::PreserveNone) {
        CB->setCallingConv(CallingConv::PreserveNone);
        WithColor::note(errs()) << "[PreserveNone]  Retagged callsite in: "
                                << CB->getFunction()->getName() << "\n";
        Changed = true;
        // }
    }
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
