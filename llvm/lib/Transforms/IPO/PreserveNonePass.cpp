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
static bool isODRorInternal(const Function &F) {
  switch (F.getLinkage()) {
  case GlobalValue::InternalLinkage:
  case GlobalValue::PrivateLinkage:
  case GlobalValue::LinkOnceODRLinkage:
  case GlobalValue::WeakODRLinkage:
    return true;
  default:
    return false;
  }
}

static bool isDirectUserOf(const CallBase &CB, const Function &F) {
  const Value *Callee = CB.getCalledOperand();
  Callee = Callee->stripPointerCasts();
  return Callee == &F;
}

static bool isSafeForPreserveNone(const Function &F) {
  if (F.isDeclaration()) return false;
  if (F.isIntrinsic())   return false;
  if (F.isVarArg())      return false;
  if (!isODRorInternal(F)) return false;     // avoid stable external ABI symbols
  if (F.hasAddressTaken()) return false;     // unknown indirect callers exist
  if (F.hasFnAttribute(Attribute::Naked)) return false;

  // Only retag from default C (or if already PreserveNone).
  if (F.getCallingConv() != CallingConv::C &&
      F.getCallingConv() != CallingConv::PreserveNone)
    return false;

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
  if (!EnablePreserveNone)
    return PreservedAnalyses::all(); // hard gate

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
      Changed = true;
    }

    for (User *U : F->users()) {
      if (auto *CB = dyn_cast<CallBase>(U)) {
        if (isDirectUserOf(*CB, *F) &&
            CB->getCallingConv() != CallingConv::PreserveNone) {
          CB->setCallingConv(CallingConv::PreserveNone);
          Changed = true;
        }
      }
    }
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
