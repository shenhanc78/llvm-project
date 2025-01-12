//===- bolt/Passes/BinaryPasses.cpp - Binary-level passes -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements multiple passes for binary optimization and analysis.
//
//===----------------------------------------------------------------------===//

#include "bolt/Core/MCPlusBuilder.h"
#include "bolt/Passes/BinaryPasses.h"
#include "bolt/Core/FunctionLayout.h"
#include "bolt/Core/ParallelUtilities.h"
#include "bolt/Passes/ReorderAlgorithm.h"
#include "bolt/Passes/ReorderFunctions.h"
#include "bolt/Utils/CommandLineOpts.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/MC/MCFragment.h"
#include "llvm/MC/MCSection.h"
#include <atomic>
#include <mutex>
#include <numeric>
#include <vector>
#include <algorithm>

#define DEBUG_TYPE "bolt-opts"

using namespace llvm;
using namespace bolt;

static const char *dynoStatsOptName(const bolt::DynoStats::Category C) {
  assert(C > bolt::DynoStats::FIRST_DYNO_STAT &&
         C < DynoStats::LAST_DYNO_STAT && "Unexpected dyno stat category.");

  static std::string OptNames[bolt::DynoStats::LAST_DYNO_STAT + 1];

  OptNames[C] = bolt::DynoStats::Description(C);

  std::replace(OptNames[C].begin(), OptNames[C].end(), ' ', '-');

  return OptNames[C].c_str();
}

namespace opts {

extern cl::OptionCategory BoltCategory;
extern cl::OptionCategory BoltOptCategory;

extern cl::opt<unsigned> Verbosity;
extern cl::opt<bool> EnableBAT;
extern cl::opt<unsigned> ExecutionCountThreshold;
extern cl::opt<bool> UpdateDebugSections;
extern cl::opt<bolt::ReorderFunctions::ReorderType> ReorderFunctions;

enum DynoStatsSortOrder : char {
  Ascending,
  Descending
};

static cl::opt<DynoStatsSortOrder> DynoStatsSortOrderOpt(
    "print-sorted-by-order",
    cl::desc("use ascending or descending order when printing functions "
             "ordered by dyno stats"),
    cl::init(DynoStatsSortOrder::Descending), cl::cat(BoltOptCategory));

cl::list<std::string>
HotTextMoveSections("hot-text-move-sections",
  cl::desc("list of sections containing functions used for hugifying hot text. "
           "BOLT makes sure these functions are not placed on the same page as "
           "the hot text. (default=\'.stub,.mover\')."),
  cl::value_desc("sec1,sec2,sec3,..."),
  cl::CommaSeparated,
  cl::ZeroOrMore,
  cl::cat(BoltCategory));

bool isHotTextMover(const BinaryFunction &Function) {
  for (std::string &SectionName : opts::HotTextMoveSections) {
    if (Function.getOriginSectionName() &&
        *Function.getOriginSectionName() == SectionName)
      return true;
  }

  return false;
}

static cl::opt<bool> MinBranchClusters(
    "min-branch-clusters",
    cl::desc("use a modified clustering algorithm geared towards minimizing "
             "branches"),
    cl::Hidden, cl::cat(BoltOptCategory));

static cl::list<Peepholes::PeepholeOpts> Peepholes(
    "peepholes", cl::CommaSeparated, cl::desc("enable peephole optimizations"),
    cl::value_desc("opt1,opt2,opt3,..."),
    cl::values(clEnumValN(Peepholes::PEEP_NONE, "none", "disable peepholes"),
               clEnumValN(Peepholes::PEEP_DOUBLE_JUMPS, "double-jumps",
                          "remove double jumps when able"),
               clEnumValN(Peepholes::PEEP_TAILCALL_TRAPS, "tailcall-traps",
                          "insert tail call traps"),
               clEnumValN(Peepholes::PEEP_USELESS_BRANCHES, "useless-branches",
                          "remove useless conditional branches"),
               clEnumValN(Peepholes::PEEP_ALL, "all",
                          "enable all peephole optimizations")),
    cl::ZeroOrMore, cl::cat(BoltOptCategory));

static cl::opt<unsigned>
    PrintFuncStat("print-function-statistics",
                  cl::desc("print statistics about basic block ordering"),
                  cl::init(0), cl::cat(BoltOptCategory));

static cl::opt<bool> PrintLargeFunctions(
    "print-large-functions",
    cl::desc("print functions that could not be overwritten due to excessive "
             "size"),
    cl::init(false), cl::cat(BoltOptCategory));

static cl::list<bolt::DynoStats::Category>
    PrintSortedBy("print-sorted-by", cl::CommaSeparated,
                  cl::desc("print functions sorted by order of dyno stats"),
                  cl::value_desc("key1,key2,key3,..."),
                  cl::values(
#define D(name, description, ...)                                              \
  clEnumValN(bolt::DynoStats::name, dynoStatsOptName(bolt::DynoStats::name),   \
             description),
                      REAL_DYNO_STATS
#undef D
                          clEnumValN(bolt::DynoStats::LAST_DYNO_STAT, "all",
                                     "sorted by all names")),
                  cl::ZeroOrMore, cl::cat(BoltOptCategory));

static cl::opt<bool>
    PrintUnknown("print-unknown",
                 cl::desc("print names of functions with unknown control flow"),
                 cl::cat(BoltCategory), cl::Hidden);

static cl::opt<bool>
    PrintUnknownCFG("print-unknown-cfg",
                    cl::desc("dump CFG of functions with unknown control flow"),
                    cl::cat(BoltCategory), cl::ReallyHidden);

// Please MSVC19 with a forward declaration: otherwise it reports an error about
// an undeclared variable inside a callback.
extern cl::opt<bolt::ReorderBasicBlocks::LayoutType> ReorderBlocks;
cl::opt<bolt::ReorderBasicBlocks::LayoutType> ReorderBlocks(
    "reorder-blocks", cl::desc("change layout of basic blocks in a function"),
    cl::init(bolt::ReorderBasicBlocks::LT_NONE),
    cl::values(
        clEnumValN(bolt::ReorderBasicBlocks::LT_NONE, "none",
                   "do not reorder basic blocks"),
        clEnumValN(bolt::ReorderBasicBlocks::LT_REVERSE, "reverse",
                   "layout blocks in reverse order"),
        clEnumValN(bolt::ReorderBasicBlocks::LT_OPTIMIZE, "normal",
                   "perform optimal layout based on profile"),
        clEnumValN(bolt::ReorderBasicBlocks::LT_OPTIMIZE_BRANCH,
                   "branch-predictor",
                   "perform optimal layout prioritizing branch "
                   "predictions"),
        clEnumValN(bolt::ReorderBasicBlocks::LT_OPTIMIZE_CACHE, "cache",
                   "perform optimal layout prioritizing I-cache "
                   "behavior"),
        clEnumValN(bolt::ReorderBasicBlocks::LT_OPTIMIZE_CACHE_PLUS, "cache+",
                   "perform layout optimizing I-cache behavior"),
        clEnumValN(bolt::ReorderBasicBlocks::LT_OPTIMIZE_EXT_TSP, "ext-tsp",
                   "perform layout optimizing I-cache behavior"),
        clEnumValN(bolt::ReorderBasicBlocks::LT_OPTIMIZE_SHUFFLE,
                   "cluster-shuffle", "perform random layout of clusters")),
    cl::ZeroOrMore, cl::cat(BoltOptCategory),
    cl::callback([](const bolt::ReorderBasicBlocks::LayoutType &option) {
      if (option == bolt::ReorderBasicBlocks::LT_OPTIMIZE_CACHE_PLUS) {
        errs() << "BOLT-WARNING: '-reorder-blocks=cache+' is deprecated, please"
               << " use '-reorder-blocks=ext-tsp' instead\n";
        ReorderBlocks = bolt::ReorderBasicBlocks::LT_OPTIMIZE_EXT_TSP;
      }
    }));

static cl::opt<unsigned> ReportBadLayout(
    "report-bad-layout",
    cl::desc("print top <uint> functions with suboptimal code layout on input"),
    cl::init(0), cl::Hidden, cl::cat(BoltOptCategory));

static cl::opt<bool>
    ReportStaleFuncs("report-stale",
                     cl::desc("print the list of functions with stale profile"),
                     cl::Hidden, cl::cat(BoltOptCategory));

enum SctcModes : char {
  SctcAlways,
  SctcPreserveDirection,
  SctcHeuristic
};

static cl::opt<SctcModes>
SctcMode("sctc-mode",
  cl::desc("mode for simplify conditional tail calls"),
  cl::init(SctcAlways),
  cl::values(clEnumValN(SctcAlways, "always", "always perform sctc"),
    clEnumValN(SctcPreserveDirection,
      "preserve",
      "only perform sctc when branch direction is "
      "preserved"),
    clEnumValN(SctcHeuristic,
      "heuristic",
      "use branch prediction data to control sctc")),
  cl::ZeroOrMore,
  cl::cat(BoltOptCategory));

static cl::opt<unsigned>
StaleThreshold("stale-threshold",
    cl::desc(
      "maximum percentage of stale functions to tolerate (default: 100)"),
    cl::init(100),
    cl::Hidden,
    cl::cat(BoltOptCategory));

static cl::opt<unsigned> TSPThreshold(
    "tsp-threshold",
    cl::desc(
        "maximum number of hot basic blocks in a function for which to use "
        "a precise TSP solution while re-ordering basic blocks"),
    cl::init(10), cl::Hidden, cl::cat(BoltOptCategory));

static cl::opt<unsigned> TopCalledLimit(
    "top-called-limit",
    cl::desc("maximum number of functions to print in top called "
             "functions section"),
    cl::init(100), cl::Hidden, cl::cat(BoltCategory));

// Profile density options, synced with llvm-profgen/ProfileGenerator.cpp
static cl::opt<int> ProfileDensityCutOffHot(
    "profile-density-cutoff-hot", cl::init(990000),
    cl::desc("Total samples cutoff for functions used to calculate "
             "profile density."));

static cl::opt<double> ProfileDensityThreshold(
    "profile-density-threshold", cl::init(60),
    cl::desc("If the profile density is below the given threshold, it "
             "will be suggested to increase the sampling rate."),
    cl::Optional);

} // namespace opts

namespace llvm {
namespace bolt {

// std::vector<std::string> CodeSizeReducedBasicBlocksMap;
// std::unordered_map<const BinaryFunction *, std::vector<std::string>> CodeSizeReducedBasicBlocksMap;
std::vector<std::string> CodeSizeReducedBasicBlocksMap;
std::vector<std::string> StackAdjustedFuncs;
std::vector<std::string> OutlineStackAdjustedFuncs;

std::unordered_map<std::string, std::string> BBHashMap;

bool BinaryFunctionPass::shouldOptimize(const BinaryFunction &BF) const {
  return BF.isSimple() && BF.getState() == BinaryFunction::State::CFG &&
         !BF.isIgnored();
}

bool BinaryFunctionPass::shouldPrint(const BinaryFunction &BF) const {
  return BF.isSimple() && !BF.isIgnored();
}

void NormalizeCFG::runOnFunction(BinaryFunction &BF) {
  uint64_t NumRemoved = 0;
  uint64_t NumDuplicateEdges = 0;
  uint64_t NeedsFixBranches = 0;
  for (BinaryBasicBlock &BB : BF) {
    if (!BB.empty())
      continue;

    if (BB.isEntryPoint() || BB.isLandingPad())
      continue;

    // Handle a dangling empty block.
    if (BB.succ_size() == 0) {
      // If an empty dangling basic block has a predecessor, it could be a
      // result of codegen for __builtin_unreachable. In such case, do not
      // remove the block.
      if (BB.pred_size() == 0) {
        BB.markValid(false);
        ++NumRemoved;
      }
      continue;
    }

    // The block should have just one successor.
    BinaryBasicBlock *Successor = BB.getSuccessor();
    assert(Successor && "invalid CFG encountered");

    // Redirect all predecessors to the successor block.
    while (!BB.pred_empty()) {
      BinaryBasicBlock *Predecessor = *BB.pred_begin();
      if (Predecessor->hasJumpTable())
        break;

      if (Predecessor == Successor)
        break;

      BinaryBasicBlock::BinaryBranchInfo &BI = Predecessor->getBranchInfo(BB);
      Predecessor->replaceSuccessor(&BB, Successor, BI.Count,
                                    BI.MispredictedCount);
      // We need to fix branches even if we failed to replace all successors
      // and remove the block.
      NeedsFixBranches = true;
    }

    if (BB.pred_empty()) {
      BB.removeAllSuccessors();
      BB.markValid(false);
      ++NumRemoved;
    }
  }

  if (NumRemoved)
    BF.eraseInvalidBBs();

  // Check for duplicate successors. Do it after the empty block elimination as
  // we can get more duplicate successors.
  for (BinaryBasicBlock &BB : BF)
    if (!BB.hasJumpTable() && BB.succ_size() == 2 &&
        BB.getConditionalSuccessor(false) == BB.getConditionalSuccessor(true))
      ++NumDuplicateEdges;

  // fixBranches() will get rid of duplicate edges and update jump instructions.
  if (NumDuplicateEdges || NeedsFixBranches)
    BF.fixBranches();

  NumDuplicateEdgesMerged += NumDuplicateEdges;
  NumBlocksRemoved += NumRemoved;
}

Error NormalizeCFG::runOnFunctions(BinaryContext &BC) {
  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_BB_LINEAR,
      [&](BinaryFunction &BF) { runOnFunction(BF); },
      [&](const BinaryFunction &BF) { return !shouldOptimize(BF); },
      "NormalizeCFG");
  if (NumBlocksRemoved)
    BC.outs() << "BOLT-INFO: removed " << NumBlocksRemoved << " empty block"
              << (NumBlocksRemoved == 1 ? "" : "s") << '\n';
  if (NumDuplicateEdgesMerged)
    BC.outs() << "BOLT-INFO: merged " << NumDuplicateEdgesMerged
              << " duplicate CFG edge"
              << (NumDuplicateEdgesMerged == 1 ? "" : "s") << '\n';
  return Error::success();
}

void EliminateUnreachableBlocks::runOnFunction(BinaryFunction &Function) {
  BinaryContext &BC = Function.getBinaryContext();
  unsigned Count;
  uint64_t Bytes;
  Function.markUnreachableBlocks();
  // LLVM_DEBUG({
  // for (BinaryBasicBlock &BB : Function) {
  //   if (!BB.isValid()) {
  //     BC.outs() << "BOLT-INFO: UCE found unreachable block " << BB.getName()
  //             << " in function " << Function << "\n";
  //     Function.dump();
  //   }
  // }
  // });
  // for (BinaryBasicBlock &BB : Function) {
  //   if (BB.getName().find("SuccBB_") != std::string::npos) { // Check for "outline_" in the block's name
  //     if (!BB.isValid()) {
  //       BC.outs() << "BOLT-INFO: UCE found unreachable block " << BB.getName()
  //                 << " in function " << Function << "\n";
  //       Function.dump();
  //     }
  //   }
  // }
  BinaryContext::IndependentCodeEmitter Emitter =
      BC.createIndependentMCCodeEmitter();
  std::tie(Count, Bytes) = Function.eraseInvalidBBs(Emitter.MCE.get());
  DeletedBlocks += Count;
  DeletedBytes += Bytes;
  if (Count) {
    auto L = BC.scopeLock();
    Modified.insert(&Function);
    if (opts::Verbosity > 0)
      BC.outs() << "BOLT-INFO: removed " << Count
                << " dead basic block(s) accounting for " << Bytes
                << " bytes in function " << Function << '\n';
  }
}

Error EliminateUnreachableBlocks::runOnFunctions(BinaryContext &BC) {
  ParallelUtilities::WorkFuncTy WorkFun = [&](BinaryFunction &BF) {
    runOnFunction(BF);
  };

  ParallelUtilities::PredicateTy SkipPredicate = [&](const BinaryFunction &BF) {
    return !shouldOptimize(BF) || BF.getLayout().block_empty();
  };

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_CONSTANT, WorkFun,
      SkipPredicate, "elimininate-unreachable");

  if (DeletedBlocks)
    BC.outs() << "BOLT-INFO: UCE removed " << DeletedBlocks << " blocks and "
              << DeletedBytes << " bytes of code\n";
  return Error::success();
}

bool ReorderBasicBlocks::shouldPrint(const BinaryFunction &BF) const {
  return (BinaryFunctionPass::shouldPrint(BF) &&
          opts::ReorderBlocks != ReorderBasicBlocks::LT_NONE);
}

bool ReorderBasicBlocks::shouldOptimize(const BinaryFunction &BF) const {
  // Apply execution count threshold
  if (BF.getKnownExecutionCount() < opts::ExecutionCountThreshold)
    return false;

  return BinaryFunctionPass::shouldOptimize(BF);
}

Error ReorderBasicBlocks::runOnFunctions(BinaryContext &BC) {
  if (opts::ReorderBlocks == ReorderBasicBlocks::LT_NONE)
    return Error::success();

  std::atomic_uint64_t ModifiedFuncCount(0);
  std::mutex FunctionEditDistanceMutex;
  DenseMap<const BinaryFunction *, uint64_t> FunctionEditDistance;

  ParallelUtilities::WorkFuncTy WorkFun = [&](BinaryFunction &BF) {
    SmallVector<const BinaryBasicBlock *, 0> OldBlockOrder;
    if (opts::PrintFuncStat > 0)
      llvm::copy(BF.getLayout().blocks(), std::back_inserter(OldBlockOrder));

    const bool LayoutChanged =
        modifyFunctionLayout(BF, opts::ReorderBlocks, opts::MinBranchClusters);
    if (LayoutChanged) {
      ModifiedFuncCount.fetch_add(1, std::memory_order_relaxed);
      if (opts::PrintFuncStat > 0) {
        const uint64_t Distance = BF.getLayout().getEditDistance(OldBlockOrder);
        std::lock_guard<std::mutex> Lock(FunctionEditDistanceMutex);
        FunctionEditDistance[&BF] = Distance;
      }
    }
  };

  ParallelUtilities::PredicateTy SkipFunc = [&](const BinaryFunction &BF) {
    return !shouldOptimize(BF);
  };

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_BB_LINEAR, WorkFun, SkipFunc,
      "ReorderBasicBlocks");
  const size_t NumAllProfiledFunctions =
      BC.NumProfiledFuncs + BC.NumStaleProfileFuncs;

  BC.outs() << "BOLT-INFO: basic block reordering modified layout of "
            << format(
                   "%zu functions (%.2lf%% of profiled, %.2lf%% of total)\n",
                   ModifiedFuncCount.load(std::memory_order_relaxed),
                   100.0 * ModifiedFuncCount.load(std::memory_order_relaxed) /
                       NumAllProfiledFunctions,
                   100.0 * ModifiedFuncCount.load(std::memory_order_relaxed) /
                       BC.getBinaryFunctions().size());

  if (opts::PrintFuncStat > 0) {
    raw_ostream &OS = BC.outs();
    // Copy all the values into vector in order to sort them
    std::map<uint64_t, BinaryFunction &> ScoreMap;
    auto &BFs = BC.getBinaryFunctions();
    for (auto It = BFs.begin(); It != BFs.end(); ++It)
      ScoreMap.insert(std::pair<uint64_t, BinaryFunction &>(
          It->second.getFunctionScore(), It->second));

    OS << "\nBOLT-INFO: Printing Function Statistics:\n\n";
    OS << "           There are " << BFs.size() << " functions in total. \n";
    OS << "           Number of functions being modified: "
       << ModifiedFuncCount.load(std::memory_order_relaxed) << "\n";
    OS << "           User asks for detailed information on top "
       << opts::PrintFuncStat << " functions. (Ranked by function score)"
       << "\n\n";
    uint64_t I = 0;
    for (std::map<uint64_t, BinaryFunction &>::reverse_iterator Rit =
             ScoreMap.rbegin();
         Rit != ScoreMap.rend() && I < opts::PrintFuncStat; ++Rit, ++I) {
      BinaryFunction &Function = Rit->second;

      OS << "           Information for function of top: " << (I + 1) << ": \n";
      OS << "             Function Score is: " << Function.getFunctionScore()
         << "\n";
      OS << "             There are " << Function.size()
         << " number of blocks in this function.\n";
      OS << "             There are " << Function.getInstructionCount()
         << " number of instructions in this function.\n";
      OS << "             The edit distance for this function is: "
         << FunctionEditDistance.lookup(&Function) << "\n\n";
    }
  }
  return Error::success();
}

bool ReorderBasicBlocks::modifyFunctionLayout(BinaryFunction &BF,
                                              LayoutType Type,
                                              bool MinBranchClusters) const {
  if (BF.size() == 0 || Type == LT_NONE)
    return false;

  BinaryFunction::BasicBlockOrderType NewLayout;
  std::unique_ptr<ReorderAlgorithm> Algo;

  // Cannot do optimal layout without profile.
  if (Type != LT_REVERSE && !BF.hasValidProfile())
    return false;

  if (Type == LT_REVERSE) {
    Algo.reset(new ReverseReorderAlgorithm());
  } else if (BF.size() <= opts::TSPThreshold && Type != LT_OPTIMIZE_SHUFFLE) {
    // Work on optimal solution if problem is small enough
    LLVM_DEBUG(dbgs() << "finding optimal block layout for " << BF << "\n");
    Algo.reset(new TSPReorderAlgorithm());
  } else {
    LLVM_DEBUG(dbgs() << "running block layout heuristics on " << BF << "\n");

    std::unique_ptr<ClusterAlgorithm> CAlgo;
    if (MinBranchClusters)
      CAlgo.reset(new MinBranchGreedyClusterAlgorithm());
    else
      CAlgo.reset(new PHGreedyClusterAlgorithm());

    switch (Type) {
    case LT_OPTIMIZE:
      Algo.reset(new OptimizeReorderAlgorithm(std::move(CAlgo)));
      break;

    case LT_OPTIMIZE_BRANCH:
      Algo.reset(new OptimizeBranchReorderAlgorithm(std::move(CAlgo)));
      break;

    case LT_OPTIMIZE_CACHE:
      Algo.reset(new OptimizeCacheReorderAlgorithm(std::move(CAlgo)));
      break;

    case LT_OPTIMIZE_EXT_TSP:
      Algo.reset(new ExtTSPReorderAlgorithm());
      break;

    case LT_OPTIMIZE_SHUFFLE:
      Algo.reset(new RandomClusterReorderAlgorithm(std::move(CAlgo)));
      break;

    default:
      llvm_unreachable("unexpected layout type");
    }
  }

  Algo->reorderBasicBlocks(BF, NewLayout);

  return BF.getLayout().update(NewLayout);
}

Error FixupBranches::runOnFunctions(BinaryContext &BC) {
  for (auto &It : BC.getBinaryFunctions()) {
    BinaryFunction &Function = It.second;
    if (!BC.shouldEmit(Function) || !Function.isSimple())
      continue;

    Function.fixBranches();
  }
  return Error::success();
}

Error FinalizeFunctions::runOnFunctions(BinaryContext &BC) {
  std::atomic<bool> HasFatal{false};
  ParallelUtilities::WorkFuncTy WorkFun = [&](BinaryFunction &BF) {
    if (!BF.finalizeCFIState()) {
      if (BC.HasRelocations) {
        BC.errs() << "BOLT-ERROR: unable to fix CFI state for function " << BF
                  << ". Exiting.\n";
        HasFatal = true;
        return;
      }
      BF.setSimple(false);
      return;
    }

    BF.setFinalized();

    // Update exception handling information.
    BF.updateEHRanges();


  };

  ParallelUtilities::PredicateTy SkipPredicate = [&](const BinaryFunction &BF) {
    return !BC.shouldEmit(BF);
  };

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_CONSTANT, WorkFun,
      SkipPredicate, "FinalizeFunctions");
  if (HasFatal)
    return createFatalBOLTError("finalize CFI state failure");

  uint64_t totalCodeSize = 0;

  uint64_t matchedBB = 0;

  for (auto &BFI : BC.getBinaryFunctions()) {

    BinaryFunction &Function = BFI.second;

    std::vector<BinaryBasicBlock *> Blocks(Function.pbegin(), Function.pend());

    for (BinaryBasicBlock *CurBB : Blocks) 
    {
        
        MCSymbol *BBLabel = CurBB->getLabel();

        std::string LabelName = BBLabel->getName().str();

        if (std::find(CodeSizeReducedBasicBlocksMap.begin(), CodeSizeReducedBasicBlocksMap.end(), LabelName) != CodeSizeReducedBasicBlocksMap.end())
        {

          matchedBB += 1;

          unsigned int Instbytes = 0;

          for (auto II = CurBB->begin(); II != CurBB->end(); ++II) {
              MCInst &Inst = *II;

              const SmallString<256> &V = BC.getInstructionBytes(Inst);
              for (auto c : V) {
                Instbytes += 1;
              }
          }

          totalCodeSize += Instbytes;

          // outs() << "BasicBlock: " << LabelName << ", StartAddr: " << Twine::utohexstr(CurBB->getInputOffset()) << ", Size: " << Instbytes << " Bytes, Total Size: " << totalCodeSize << " Bytes\n";

        }
    }
  }

  // for (const auto &BBName : CodeSizeReducedBasicBlocksMap) {
  //     outs() << "BasicBlock: " << BBName->getLabel() << ", Size: " << BBName->getOriginalSize() << " Bytes\n";
  // }

  // for (const auto &Entry : CodeSizeReducedBasicBlocksMap) {
  //     const BinaryFunction *OutlinedFunction = Entry.first;
  //     const std::vector<std::string> &BBNames = Entry.second;

  //     for (const auto &BBName : BBNames) 
      
  //     {

  //       std::string OutlineBBName = BBName;

  //       MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

  //       auto OutlineBB = OutlinedFunction->getBasicBlockForLabel(OutlineBBLabel);

  //       outs() << "Function: " << Function.getPrintName() << ", BasicBlock: " << OutlineBBName << ", Size: " << OutlineBB->getOriginalSize() << " Bytes\n";

  //     }
  // }

  /*for (auto &BFI : BC.getBinaryFunctions()) {

    BinaryFunction &Function = BFI.second;

    if (std::find(CodeSizeReducedBasicBlocksMap.begin(), CodeSizeReducedBasicBlocksMap.end(), Function.getPrintName()) != CodeSizeReducedBasicBlocksMap.end())
    {
        totalCodeSize += Function.getSize();
        // outs() << "Function: " << Function.getPrintName() << ", Size: " << Function.getSize() << " \n";
    }
  }

  outs() << "BOLT-INFO: Total Sizes of the functions of interest from Code Size Reduction: " << totalCodeSize << " Bytes\n";*/
  outs() << "\n************\n";
  outs() << "BOLT-INFO: Total Sizes of " << matchedBB << " Redundant BBs after Outlining: " << totalCodeSize << " Bytes\n";
  outs() << "************\n\n";
  return Error::success();


}

Error CheckLargeFunctions::runOnFunctions(BinaryContext &BC) {
  if (BC.HasRelocations)
    return Error::success();

  // If the function wouldn't fit, mark it as non-simple. Otherwise, we may emit
  // incorrect meta data.
  ParallelUtilities::WorkFuncTy WorkFun = [&](BinaryFunction &BF) {
    uint64_t HotSize, ColdSize;
    std::tie(HotSize, ColdSize) =
        BC.calculateEmittedSize(BF, /*FixBranches=*/false);
    if (HotSize > BF.getMaxSize()) {
      if (opts::PrintLargeFunctions)
        BC.outs() << "BOLT-INFO: " << BF << " size exceeds allocated space by "
                  << (HotSize - BF.getMaxSize()) << " bytes\n";
      BF.setSimple(false);
    }
  };

  ParallelUtilities::PredicateTy SkipFunc = [&](const BinaryFunction &BF) {
    return !shouldOptimize(BF);
  };

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_INST_LINEAR, WorkFun,
      SkipFunc, "CheckLargeFunctions");

  return Error::success();
}

bool CheckLargeFunctions::shouldOptimize(const BinaryFunction &BF) const {
  // Unlike other passes, allow functions in non-CFG state.
  return BF.isSimple() && !BF.isIgnored();
}

Error LowerAnnotations::runOnFunctions(BinaryContext &BC) {
  // Convert GnuArgsSize annotations into CFIs.
  for (BinaryFunction *BF : BC.getAllBinaryFunctions()) {
    for (FunctionFragment &FF : BF->getLayout().fragments()) {
      // Reset at the start of the new fragment.
      int64_t CurrentGnuArgsSize = 0;

      for (BinaryBasicBlock *const BB : FF) {
        for (auto II = BB->begin(); II != BB->end(); ++II) {
          if (!BF->usesGnuArgsSize() || !BC.MIB->isInvoke(*II))
            continue;

          const int64_t NewGnuArgsSize = BC.MIB->getGnuArgsSize(*II);
          assert(NewGnuArgsSize >= 0 && "Expected non-negative GNU_args_size.");
          if (NewGnuArgsSize == CurrentGnuArgsSize)
            continue;

          auto InsertII = BF->addCFIInstruction(
              BB, II,
              MCCFIInstruction::createGnuArgsSize(nullptr, NewGnuArgsSize));
          CurrentGnuArgsSize = NewGnuArgsSize;
          II = std::next(InsertII);
        }
      }
    }
  }
  return Error::success();
}

// Check for dirty state in MCSymbol objects that might be a consequence
// of running calculateEmittedSize() in parallel, during split functions
// pass. If an inconsistent state is found (symbol already registered or
// already defined), clean it.
Error CleanMCState::runOnFunctions(BinaryContext &BC) {
  MCContext &Ctx = *BC.Ctx;
  for (const auto &SymMapEntry : Ctx.getSymbols()) {
    const MCSymbol *S = SymMapEntry.getValue().Symbol;
    if (!S)
      continue;
    if (S->isDefined()) {
      LLVM_DEBUG(dbgs() << "BOLT-DEBUG: Symbol \"" << S->getName()
                        << "\" is already defined\n");
      const_cast<MCSymbol *>(S)->setUndefined();
    }
    if (S->isRegistered()) {
      LLVM_DEBUG(dbgs() << "BOLT-DEBUG: Symbol \"" << S->getName()
                        << "\" is already registered\n");
      const_cast<MCSymbol *>(S)->setIsRegistered(false);
    }
    LLVM_DEBUG(if (S->isVariable()) {
      dbgs() << "BOLT-DEBUG: Symbol \"" << S->getName() << "\" is variable\n";
    });
  }
  return Error::success();
}

// This peephole fixes jump instructions that jump to another basic
// block with a single jump instruction, e.g.
//
// B0: ...
//     jmp  B1   (or jcc B1)
//
// B1: jmp  B2
//
// ->
//
// B0: ...
//     jmp  B2   (or jcc B2)
//
static uint64_t fixDoubleJumps(BinaryFunction &Function, bool MarkInvalid) {
  uint64_t NumDoubleJumps = 0;

  MCContext *Ctx = Function.getBinaryContext().Ctx.get();
  MCPlusBuilder *MIB = Function.getBinaryContext().MIB.get();
  for (BinaryBasicBlock &BB : Function) {
    auto checkAndPatch = [&](BinaryBasicBlock *Pred, BinaryBasicBlock *Succ,
                             const MCSymbol *SuccSym,
                             std::optional<uint32_t> Offset) {
      // Ignore infinite loop jumps or fallthrough tail jumps.
      if (Pred == Succ || Succ == &BB)
        return false;

      if (Succ) {
        const MCSymbol *TBB = nullptr;
        const MCSymbol *FBB = nullptr;
        MCInst *CondBranch = nullptr;
        MCInst *UncondBranch = nullptr;
        bool Res = Pred->analyzeBranch(TBB, FBB, CondBranch, UncondBranch);
        if (!Res) {
          LLVM_DEBUG(dbgs() << "analyzeBranch failed in peepholes in block:\n";
                     Pred->dump());
          return false;
        }
        Pred->replaceSuccessor(&BB, Succ);

        // We must patch up any existing branch instructions to match up
        // with the new successor.
        assert((CondBranch || (!CondBranch && Pred->succ_size() == 1)) &&
               "Predecessor block has inconsistent number of successors");
        if (CondBranch && MIB->getTargetSymbol(*CondBranch) == BB.getLabel()) {
          MIB->replaceBranchTarget(*CondBranch, Succ->getLabel(), Ctx);
        } else if (UncondBranch &&
                   MIB->getTargetSymbol(*UncondBranch) == BB.getLabel()) {
          MIB->replaceBranchTarget(*UncondBranch, Succ->getLabel(), Ctx);
        } else if (!UncondBranch) {
          assert(Function.getLayout().getBasicBlockAfter(Pred, false) != Succ &&
                 "Don't add an explicit jump to a fallthrough block.");
          Pred->addBranchInstruction(Succ);
        }
      } else {
        // Succ will be null in the tail call case.  In this case we
        // need to explicitly add a tail call instruction.
        MCInst *Branch = Pred->getLastNonPseudoInstr();
        if (Branch && MIB->isUnconditionalBranch(*Branch)) {
          assert(MIB->getTargetSymbol(*Branch) == BB.getLabel());
          Pred->removeSuccessor(&BB);
          Pred->eraseInstruction(Pred->findInstruction(Branch));
          Pred->addTailCallInstruction(SuccSym);
          if (Offset) {
            MCInst *TailCall = Pred->getLastNonPseudoInstr();
            assert(TailCall);
            MIB->setOffset(*TailCall, *Offset);
          }
        } else {
          return false;
        }
      }

      ++NumDoubleJumps;
      LLVM_DEBUG(dbgs() << "Removed double jump in " << Function << " from "
                        << Pred->getName() << " -> " << BB.getName() << " to "
                        << Pred->getName() << " -> " << SuccSym->getName()
                        << (!Succ ? " (tail)\n" : "\n"));

      return true;
    };

    if (BB.getNumNonPseudos() != 1 || BB.isLandingPad())
      continue;

    MCInst *Inst = BB.getFirstNonPseudoInstr();
    const bool IsTailCall = MIB->isTailCall(*Inst);

    if (!MIB->isUnconditionalBranch(*Inst) && !IsTailCall)
      continue;

    // If we operate after SCTC make sure it's not a conditional tail call.
    if (IsTailCall && MIB->isConditionalBranch(*Inst))
      continue;

    const MCSymbol *SuccSym = MIB->getTargetSymbol(*Inst);
    BinaryBasicBlock *Succ = BB.getSuccessor();

    if (((!Succ || &BB == Succ) && !IsTailCall) || (IsTailCall && !SuccSym))
      continue;

    std::vector<BinaryBasicBlock *> Preds = {BB.pred_begin(), BB.pred_end()};

    for (BinaryBasicBlock *Pred : Preds) {
      if (Pred->isLandingPad())
        continue;

      if (Pred->getSuccessor() == &BB ||
          (Pred->getConditionalSuccessor(true) == &BB && !IsTailCall) ||
          Pred->getConditionalSuccessor(false) == &BB)
        if (checkAndPatch(Pred, Succ, SuccSym, MIB->getOffset(*Inst)) &&
            MarkInvalid)
          BB.markValid(BB.pred_size() != 0 || BB.isLandingPad() ||
                       BB.isEntryPoint());
    }
  }

  return NumDoubleJumps;
}

bool SimplifyConditionalTailCalls::shouldRewriteBranch(
    const BinaryBasicBlock *PredBB, const MCInst &CondBranch,
    const BinaryBasicBlock *BB, const bool DirectionFlag) {
  if (BeenOptimized.count(PredBB))
    return false;

  const bool IsForward = BinaryFunction::isForwardBranch(PredBB, BB);

  if (IsForward)
    ++NumOrigForwardBranches;
  else
    ++NumOrigBackwardBranches;

  if (opts::SctcMode == opts::SctcAlways)
    return true;

  if (opts::SctcMode == opts::SctcPreserveDirection)
    return IsForward == DirectionFlag;

  const ErrorOr<std::pair<double, double>> Frequency =
      PredBB->getBranchStats(BB);

  // It's ok to rewrite the conditional branch if the new target will be
  // a backward branch.

  // If no data available for these branches, then it should be ok to
  // do the optimization since it will reduce code size.
  if (Frequency.getError())
    return true;

  // TODO: should this use misprediction frequency instead?
  const bool Result = (IsForward && Frequency.get().first >= 0.5) ||
                      (!IsForward && Frequency.get().first <= 0.5);

  return Result == DirectionFlag;
}

uint64_t SimplifyConditionalTailCalls::fixTailCalls(BinaryFunction &BF) {
  // Need updated indices to correctly detect branch' direction.
  BF.getLayout().updateLayoutIndices();
  BF.markUnreachableBlocks();

  MCPlusBuilder *MIB = BF.getBinaryContext().MIB.get();
  MCContext *Ctx = BF.getBinaryContext().Ctx.get();
  uint64_t NumLocalCTCCandidates = 0;
  uint64_t NumLocalCTCs = 0;
  uint64_t LocalCTCTakenCount = 0;
  uint64_t LocalCTCExecCount = 0;
  std::vector<std::pair<BinaryBasicBlock *, const BinaryBasicBlock *>>
      NeedsUncondBranch;

  // Will block be deleted by UCE?
  auto isValid = [](const BinaryBasicBlock *BB) {
    return (BB->pred_size() != 0 || BB->isLandingPad() || BB->isEntryPoint());
  };

  for (BinaryBasicBlock *BB : BF.getLayout().blocks()) {
    // Locate BB with a single direct tail-call instruction.
    if (BB->getNumNonPseudos() != 1)
      continue;

    MCInst *Instr = BB->getFirstNonPseudoInstr();
    if (!MIB->isTailCall(*Instr) || MIB->isConditionalBranch(*Instr))
      continue;

    const MCSymbol *CalleeSymbol = MIB->getTargetSymbol(*Instr);
    if (!CalleeSymbol)
      continue;

    // Detect direction of the possible conditional tail call.
    const bool IsForwardCTC = BF.isForwardCall(CalleeSymbol);

    // Iterate through all predecessors.
    for (BinaryBasicBlock *PredBB : BB->predecessors()) {
      BinaryBasicBlock *CondSucc = PredBB->getConditionalSuccessor(true);
      if (!CondSucc)
        continue;

      ++NumLocalCTCCandidates;

      const MCSymbol *TBB = nullptr;
      const MCSymbol *FBB = nullptr;
      MCInst *CondBranch = nullptr;
      MCInst *UncondBranch = nullptr;
      bool Result = PredBB->analyzeBranch(TBB, FBB, CondBranch, UncondBranch);

      // analyzeBranch() can fail due to unusual branch instructions, e.g. jrcxz
      if (!Result) {
        LLVM_DEBUG(dbgs() << "analyzeBranch failed in SCTC in block:\n";
                   PredBB->dump());
        continue;
      }

      assert(Result && "internal error analyzing conditional branch");
      assert(CondBranch && "conditional branch expected");

      // Skip dynamic branches for now.
      if (BF.getBinaryContext().MIB->isDynamicBranch(*CondBranch))
        continue;

      // It's possible that PredBB is also a successor to BB that may have
      // been processed by a previous iteration of the SCTC loop, in which
      // case it may have been marked invalid.  We should skip rewriting in
      // this case.
      if (!PredBB->isValid()) {
        assert(PredBB->isSuccessor(BB) &&
               "PredBB should be valid if it is not a successor to BB");
        continue;
      }

      // We don't want to reverse direction of the branch in new order
      // without further profile analysis.
      const bool DirectionFlag = CondSucc == BB ? IsForwardCTC : !IsForwardCTC;
      if (!shouldRewriteBranch(PredBB, *CondBranch, BB, DirectionFlag))
        continue;

      // Record this block so that we don't try to optimize it twice.
      BeenOptimized.insert(PredBB);

      uint64_t Count = 0;
      if (CondSucc != BB) {
        // Patch the new target address into the conditional branch.
        MIB->reverseBranchCondition(*CondBranch, CalleeSymbol, Ctx);
        // Since we reversed the condition on the branch we need to change
        // the target for the unconditional branch or add a unconditional
        // branch to the old target.  This has to be done manually since
        // fixupBranches is not called after SCTC.
        NeedsUncondBranch.emplace_back(PredBB, CondSucc);
        Count = PredBB->getFallthroughBranchInfo().Count;
      } else {
        // Change destination of the conditional branch.
        MIB->replaceBranchTarget(*CondBranch, CalleeSymbol, Ctx);
        Count = PredBB->getTakenBranchInfo().Count;
      }
      const uint64_t CTCTakenFreq =
          Count == BinaryBasicBlock::COUNT_NO_PROFILE ? 0 : Count;

      // Annotate it, so "isCall" returns true for this jcc
      MIB->setConditionalTailCall(*CondBranch);
      // Add info about the conditional tail call frequency, otherwise this
      // info will be lost when we delete the associated BranchInfo entry
      auto &CTCAnnotation =
          MIB->getOrCreateAnnotationAs<uint64_t>(*CondBranch, "CTCTakenCount");
      CTCAnnotation = CTCTakenFreq;
      // Preserve Offset annotation, used in BAT.
      // Instr is a direct tail call instruction that was created when CTCs are
      // first expanded, and has the original CTC offset set.
      if (std::optional<uint32_t> Offset = MIB->getOffset(*Instr))
        MIB->setOffset(*CondBranch, *Offset);

      // Remove the unused successor which may be eliminated later
      // if there are no other users.
      PredBB->removeSuccessor(BB);
      // Update BB execution count
      if (CTCTakenFreq && CTCTakenFreq <= BB->getKnownExecutionCount())
        BB->setExecutionCount(BB->getExecutionCount() - CTCTakenFreq);
      else if (CTCTakenFreq > BB->getKnownExecutionCount())
        BB->setExecutionCount(0);

      ++NumLocalCTCs;
      LocalCTCTakenCount += CTCTakenFreq;
      LocalCTCExecCount += PredBB->getKnownExecutionCount();
    }

    // Remove the block from CFG if all predecessors were removed.
    BB->markValid(isValid(BB));
  }

  // Add unconditional branches at the end of BBs to new successors
  // as long as the successor is not a fallthrough.
  for (auto &Entry : NeedsUncondBranch) {
    BinaryBasicBlock *PredBB = Entry.first;
    const BinaryBasicBlock *CondSucc = Entry.second;

    const MCSymbol *TBB = nullptr;
    const MCSymbol *FBB = nullptr;
    MCInst *CondBranch = nullptr;
    MCInst *UncondBranch = nullptr;
    PredBB->analyzeBranch(TBB, FBB, CondBranch, UncondBranch);

    // Find the next valid block.  Invalid blocks will be deleted
    // so they shouldn't be considered fallthrough targets.
    const BinaryBasicBlock *NextBlock =
        BF.getLayout().getBasicBlockAfter(PredBB, false);
    while (NextBlock && !isValid(NextBlock))
      NextBlock = BF.getLayout().getBasicBlockAfter(NextBlock, false);

    // Get the unconditional successor to this block.
    const BinaryBasicBlock *PredSucc = PredBB->getSuccessor();
    assert(PredSucc && "The other branch should be a tail call");

    const bool HasFallthrough = (NextBlock && PredSucc == NextBlock);

    if (UncondBranch) {
      if (HasFallthrough)
        PredBB->eraseInstruction(PredBB->findInstruction(UncondBranch));
      else
        MIB->replaceBranchTarget(*UncondBranch, CondSucc->getLabel(), Ctx);
    } else if (!HasFallthrough) {
      MCInst Branch;
      MIB->createUncondBranch(Branch, CondSucc->getLabel(), Ctx);
      PredBB->addInstruction(Branch);
    }
  }

  if (NumLocalCTCs > 0) {
    NumDoubleJumps += fixDoubleJumps(BF, true);
    // Clean-up unreachable tail-call blocks.
    const std::pair<unsigned, uint64_t> Stats = BF.eraseInvalidBBs();
    DeletedBlocks += Stats.first;
    DeletedBytes += Stats.second;

    assert(BF.validateCFG());
  }

  LLVM_DEBUG(dbgs() << "BOLT: created " << NumLocalCTCs
                    << " conditional tail calls from a total of "
                    << NumLocalCTCCandidates << " candidates in function " << BF
                    << ". CTCs execution count for this function is "
                    << LocalCTCExecCount << " and CTC taken count is "
                    << LocalCTCTakenCount << "\n";);

  NumTailCallsPatched += NumLocalCTCs;
  NumCandidateTailCalls += NumLocalCTCCandidates;
  CTCExecCount += LocalCTCExecCount;
  CTCTakenCount += LocalCTCTakenCount;

  return NumLocalCTCs > 0;
}

Error SimplifyConditionalTailCalls::runOnFunctions(BinaryContext &BC) {
  if (!BC.isX86())
    return Error::success();

  for (auto &It : BC.getBinaryFunctions()) {
    BinaryFunction &Function = It.second;

    if (!shouldOptimize(Function))
      continue;

    if (fixTailCalls(Function)) {
      Modified.insert(&Function);
      Function.setHasCanonicalCFG(false);
    }
  }

  if (NumTailCallsPatched)
    BC.outs() << "BOLT-INFO: SCTC: patched " << NumTailCallsPatched
              << " tail calls (" << NumOrigForwardBranches << " forward)"
              << " tail calls (" << NumOrigBackwardBranches << " backward)"
              << " from a total of " << NumCandidateTailCalls
              << " while removing " << NumDoubleJumps << " double jumps"
              << " and removing " << DeletedBlocks << " basic blocks"
              << " totalling " << DeletedBytes
              << " bytes of code. CTCs total execution count is "
              << CTCExecCount << " and the number of times CTCs are taken is "
              << CTCTakenCount << "\n";
  return Error::success();
}

uint64_t ShortenInstructions::shortenInstructions(BinaryFunction &Function) {
  uint64_t Count = 0;
  const BinaryContext &BC = Function.getBinaryContext();
  for (BinaryBasicBlock &BB : Function) {
    for (MCInst &Inst : BB) {
      // Skip shortening instructions with Size annotation.
      if (BC.MIB->getSize(Inst))
        continue;

      MCInst OriginalInst;
      if (opts::Verbosity > 2)
        OriginalInst = Inst;

      if (!BC.MIB->shortenInstruction(Inst, *BC.STI))
        continue;

      if (opts::Verbosity > 2) {
        BC.scopeLock();
        BC.outs() << "BOLT-INFO: shortening:\nBOLT-INFO:    ";
        BC.printInstruction(BC.outs(), OriginalInst, 0, &Function);
        BC.outs() << "BOLT-INFO: to:";
        BC.printInstruction(BC.outs(), Inst, 0, &Function);
      }

      ++Count;
    }
  }

  return Count;
}

Error ShortenInstructions::runOnFunctions(BinaryContext &BC) {
  std::atomic<uint64_t> NumShortened{0};
  if (!BC.isX86())
    return Error::success();

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_INST_LINEAR,
      [&](BinaryFunction &BF) { NumShortened += shortenInstructions(BF); },
      nullptr, "ShortenInstructions");

  if (NumShortened)
    BC.outs() << "BOLT-INFO: " << NumShortened
              << " instructions were shortened\n";
  return Error::success();
}

void Peepholes::addTailcallTraps(BinaryFunction &Function) {
  MCPlusBuilder *MIB = Function.getBinaryContext().MIB.get();
  for (BinaryBasicBlock &BB : Function) {
    MCInst *Inst = BB.getLastNonPseudoInstr();
    if (Inst && MIB->isTailCall(*Inst) && MIB->isIndirectBranch(*Inst)) {
      MCInst Trap;
      MIB->createTrap(Trap);
      BB.addInstruction(Trap);
      ++TailCallTraps;
    }
  }
}

void Peepholes::removeUselessCondBranches(BinaryFunction &Function) {
  for (BinaryBasicBlock &BB : Function) {
    if (BB.succ_size() != 2)
      continue;

    BinaryBasicBlock *CondBB = BB.getConditionalSuccessor(true);
    BinaryBasicBlock *UncondBB = BB.getConditionalSuccessor(false);
    if (CondBB != UncondBB)
      continue;

    const MCSymbol *TBB = nullptr;
    const MCSymbol *FBB = nullptr;
    MCInst *CondBranch = nullptr;
    MCInst *UncondBranch = nullptr;
    bool Result = BB.analyzeBranch(TBB, FBB, CondBranch, UncondBranch);

    // analyzeBranch() can fail due to unusual branch instructions,
    // e.g. jrcxz, or jump tables (indirect jump).
    if (!Result || !CondBranch)
      continue;

    BB.removeDuplicateConditionalSuccessor(CondBranch);
    ++NumUselessCondBranches;
  }
}

Error Peepholes::runOnFunctions(BinaryContext &BC) {
  const char Opts =
      std::accumulate(opts::Peepholes.begin(), opts::Peepholes.end(), 0,
                      [](const char A, const PeepholeOpts B) { return A | B; });
  if (Opts == PEEP_NONE)
    return Error::success();

  for (auto &It : BC.getBinaryFunctions()) {
    BinaryFunction &Function = It.second;
    if (shouldOptimize(Function)) {
      if (Opts & PEEP_DOUBLE_JUMPS)
        NumDoubleJumps += fixDoubleJumps(Function, false);
      if (Opts & PEEP_TAILCALL_TRAPS)
        addTailcallTraps(Function);
      if (Opts & PEEP_USELESS_BRANCHES)
        removeUselessCondBranches(Function);
      assert(Function.validateCFG());
    }
  }
  BC.outs() << "BOLT-INFO: Peephole: " << NumDoubleJumps
            << " double jumps patched.\n"
            << "BOLT-INFO: Peephole: " << TailCallTraps
            << " tail call traps inserted.\n"
            << "BOLT-INFO: Peephole: " << NumUselessCondBranches
            << " useless conditional branches removed.\n";
  return Error::success();
}

bool SimplifyRODataLoads::simplifyRODataLoads(BinaryFunction &BF) {
  BinaryContext &BC = BF.getBinaryContext();
  MCPlusBuilder *MIB = BC.MIB.get();

  uint64_t NumLocalLoadsSimplified = 0;
  uint64_t NumDynamicLocalLoadsSimplified = 0;
  uint64_t NumLocalLoadsFound = 0;
  uint64_t NumDynamicLocalLoadsFound = 0;

  for (BinaryBasicBlock *BB : BF.getLayout().blocks()) {
    for (MCInst &Inst : *BB) {
      unsigned Opcode = Inst.getOpcode();
      const MCInstrDesc &Desc = BC.MII->get(Opcode);

      // Skip instructions that do not load from memory.
      if (!Desc.mayLoad())
        continue;

      // Try to statically evaluate the target memory address;
      uint64_t TargetAddress;

      if (MIB->hasPCRelOperand(Inst)) {
        // Try to find the symbol that corresponds to the PC-relative operand.
        MCOperand *DispOpI = MIB->getMemOperandDisp(Inst);
        assert(DispOpI != Inst.end() && "expected PC-relative displacement");
        assert(DispOpI->isExpr() &&
               "found PC-relative with non-symbolic displacement");

        // Get displacement symbol.
        const MCSymbol *DisplSymbol;
        uint64_t DisplOffset;

        std::tie(DisplSymbol, DisplOffset) =
            MIB->getTargetSymbolInfo(DispOpI->getExpr());

        if (!DisplSymbol)
          continue;

        // Look up the symbol address in the global symbols map of the binary
        // context object.
        BinaryData *BD = BC.getBinaryDataByName(DisplSymbol->getName());
        if (!BD)
          continue;
        TargetAddress = BD->getAddress() + DisplOffset;
      } else if (!MIB->evaluateMemOperandTarget(Inst, TargetAddress)) {
        continue;
      }

      // Get the contents of the section containing the target address of the
      // memory operand. We are only interested in read-only sections.
      ErrorOr<BinarySection &> DataSection =
          BC.getSectionForAddress(TargetAddress);
      if (!DataSection || DataSection->isWritable())
        continue;

      if (BC.getRelocationAt(TargetAddress) ||
          BC.getDynamicRelocationAt(TargetAddress))
        continue;

      uint32_t Offset = TargetAddress - DataSection->getAddress();
      StringRef ConstantData = DataSection->getContents();

      ++NumLocalLoadsFound;
      if (BB->hasProfile())
        NumDynamicLocalLoadsFound += BB->getExecutionCount();

      if (MIB->replaceMemOperandWithImm(Inst, ConstantData, Offset)) {
        ++NumLocalLoadsSimplified;
        if (BB->hasProfile())
          NumDynamicLocalLoadsSimplified += BB->getExecutionCount();
      }
    }
  }

  NumLoadsFound += NumLocalLoadsFound;
  NumDynamicLoadsFound += NumDynamicLocalLoadsFound;
  NumLoadsSimplified += NumLocalLoadsSimplified;
  NumDynamicLoadsSimplified += NumDynamicLocalLoadsSimplified;

  return NumLocalLoadsSimplified > 0;
}

Error SimplifyRODataLoads::runOnFunctions(BinaryContext &BC) {
  for (auto &It : BC.getBinaryFunctions()) {
    BinaryFunction &Function = It.second;
    if (shouldOptimize(Function) && simplifyRODataLoads(Function))
      Modified.insert(&Function);
  }

  BC.outs() << "BOLT-INFO: simplified " << NumLoadsSimplified << " out of "
            << NumLoadsFound << " loads from a statically computed address.\n"
            << "BOLT-INFO: dynamic loads simplified: "
            << NumDynamicLoadsSimplified << "\n"
            << "BOLT-INFO: dynamic loads found: " << NumDynamicLoadsFound
            << "\n";
  return Error::success();
}

Error AssignSections::runOnFunctions(BinaryContext &BC) {
  for (BinaryFunction *Function : BC.getInjectedBinaryFunctions()) {
    Function->setCodeSectionName(BC.getInjectedCodeSectionName());
    Function->setColdCodeSectionName(BC.getInjectedColdCodeSectionName());
  }

  // In non-relocation mode functions have pre-assigned section names.
  if (!BC.HasRelocations)
    return Error::success();

  const bool UseColdSection =
      BC.NumProfiledFuncs > 0 ||
      opts::ReorderFunctions == ReorderFunctions::RT_USER;
  for (auto &BFI : BC.getBinaryFunctions()) {
    BinaryFunction &Function = BFI.second;
    if (opts::isHotTextMover(Function)) {
      Function.setCodeSectionName(BC.getHotTextMoverSectionName());
      Function.setColdCodeSectionName(BC.getHotTextMoverSectionName());
      continue;
    }

    if (!UseColdSection || Function.hasValidIndex())
      Function.setCodeSectionName(BC.getMainCodeSectionName());
    else
      Function.setCodeSectionName(BC.getColdCodeSectionName());

    if (Function.isSplit())
      Function.setColdCodeSectionName(BC.getColdCodeSectionName());
  }
  return Error::success();
}

Error PrintProfileStats::runOnFunctions(BinaryContext &BC) {
  double FlowImbalanceMean = 0.0;
  size_t NumBlocksConsidered = 0;
  double WorstBias = 0.0;
  const BinaryFunction *WorstBiasFunc = nullptr;

  // For each function CFG, we fill an IncomingMap with the sum of the frequency
  // of incoming edges for each BB. Likewise for each OutgoingMap and the sum
  // of the frequency of outgoing edges.
  using FlowMapTy = std::unordered_map<const BinaryBasicBlock *, uint64_t>;
  std::unordered_map<const BinaryFunction *, FlowMapTy> TotalIncomingMaps;
  std::unordered_map<const BinaryFunction *, FlowMapTy> TotalOutgoingMaps;

  // Compute mean
  for (const auto &BFI : BC.getBinaryFunctions()) {
    const BinaryFunction &Function = BFI.second;
    if (Function.empty() || !Function.isSimple())
      continue;
    FlowMapTy &IncomingMap = TotalIncomingMaps[&Function];
    FlowMapTy &OutgoingMap = TotalOutgoingMaps[&Function];
    for (const BinaryBasicBlock &BB : Function) {
      uint64_t TotalOutgoing = 0ULL;
      auto SuccBIIter = BB.branch_info_begin();
      for (BinaryBasicBlock *Succ : BB.successors()) {
        uint64_t Count = SuccBIIter->Count;
        if (Count == BinaryBasicBlock::COUNT_NO_PROFILE || Count == 0) {
          ++SuccBIIter;
          continue;
        }
        TotalOutgoing += Count;
        IncomingMap[Succ] += Count;
        ++SuccBIIter;
      }
      OutgoingMap[&BB] = TotalOutgoing;
    }

    size_t NumBlocks = 0;
    double Mean = 0.0;
    for (const BinaryBasicBlock &BB : Function) {
      // Do not compute score for low frequency blocks, entry or exit blocks
      if (IncomingMap[&BB] < 100 || OutgoingMap[&BB] == 0 || BB.isEntryPoint())
        continue;
      ++NumBlocks;
      const double Difference = (double)OutgoingMap[&BB] - IncomingMap[&BB];
      Mean += fabs(Difference / IncomingMap[&BB]);
    }

    FlowImbalanceMean += Mean;
    NumBlocksConsidered += NumBlocks;
    if (!NumBlocks)
      continue;
    double FuncMean = Mean / NumBlocks;
    if (FuncMean > WorstBias) {
      WorstBias = FuncMean;
      WorstBiasFunc = &Function;
    }
  }
  if (NumBlocksConsidered > 0)
    FlowImbalanceMean /= NumBlocksConsidered;

  // Compute standard deviation
  NumBlocksConsidered = 0;
  double FlowImbalanceVar = 0.0;
  for (const auto &BFI : BC.getBinaryFunctions()) {
    const BinaryFunction &Function = BFI.second;
    if (Function.empty() || !Function.isSimple())
      continue;
    FlowMapTy &IncomingMap = TotalIncomingMaps[&Function];
    FlowMapTy &OutgoingMap = TotalOutgoingMaps[&Function];
    for (const BinaryBasicBlock &BB : Function) {
      if (IncomingMap[&BB] < 100 || OutgoingMap[&BB] == 0)
        continue;
      ++NumBlocksConsidered;
      const double Difference = (double)OutgoingMap[&BB] - IncomingMap[&BB];
      FlowImbalanceVar +=
          pow(fabs(Difference / IncomingMap[&BB]) - FlowImbalanceMean, 2);
    }
  }
  if (NumBlocksConsidered) {
    FlowImbalanceVar /= NumBlocksConsidered;
    FlowImbalanceVar = sqrt(FlowImbalanceVar);
  }

  // Report to user
  BC.outs() << format("BOLT-INFO: Profile bias score: %.4lf%% StDev: %.4lf%%\n",
                      (100.0 * FlowImbalanceMean), (100.0 * FlowImbalanceVar));
  if (WorstBiasFunc && opts::Verbosity >= 1) {
    BC.outs() << "Worst average bias observed in "
              << WorstBiasFunc->getPrintName() << "\n";
    LLVM_DEBUG(WorstBiasFunc->dump());
  }
  return Error::success();
}

Error PrintProgramStats::runOnFunctions(BinaryContext &BC) {
  uint64_t NumRegularFunctions = 0;
  uint64_t NumStaleProfileFunctions = 0;
  uint64_t NumAllStaleFunctions = 0;
  uint64_t NumInferredFunctions = 0;
  uint64_t NumNonSimpleProfiledFunctions = 0;
  uint64_t NumUnknownControlFlowFunctions = 0;
  uint64_t TotalSampleCount = 0;
  uint64_t StaleSampleCount = 0;
  uint64_t InferredSampleCount = 0;
  std::vector<const BinaryFunction *> ProfiledFunctions;
  std::vector<std::pair<double, uint64_t>> FuncDensityList;
  const char *StaleFuncsHeader = "BOLT-INFO: Functions with stale profile:\n";
  for (auto &BFI : BC.getBinaryFunctions()) {
    const BinaryFunction &Function = BFI.second;

    // Ignore PLT functions for stats.
    if (Function.isPLTFunction())
      continue;

    // Adjustment for BAT mode: the profile for BOLT split fragments is combined
    // so only count the hot fragment.
    const uint64_t Address = Function.getAddress();
    bool IsHotParentOfBOLTSplitFunction = !Function.getFragments().empty() &&
                                          BAT && BAT->isBATFunction(Address) &&
                                          !BAT->fetchParentAddress(Address);

    ++NumRegularFunctions;

    // In BOLTed binaries split functions are non-simple (due to non-relocation
    // mode), but the original function is known to be simple and we have a
    // valid profile for it.
    if (!Function.isSimple() && !IsHotParentOfBOLTSplitFunction) {
      if (Function.hasProfile())
        ++NumNonSimpleProfiledFunctions;
      continue;
    }

    if (Function.hasUnknownControlFlow()) {
      if (opts::PrintUnknownCFG)
        Function.dump();
      else if (opts::PrintUnknown)
        BC.errs() << "function with unknown control flow: " << Function << '\n';

      ++NumUnknownControlFlowFunctions;
    }

    if (!Function.hasProfile())
      continue;

    uint64_t SampleCount = Function.getRawBranchCount();
    TotalSampleCount += SampleCount;

    if (Function.hasValidProfile()) {
      ProfiledFunctions.push_back(&Function);
      if (Function.hasInferredProfile()) {
        ++NumInferredFunctions;
        InferredSampleCount += SampleCount;
        ++NumAllStaleFunctions;
      }
    } else {
      if (opts::ReportStaleFuncs) {
        BC.outs() << StaleFuncsHeader;
        StaleFuncsHeader = "";
        BC.outs() << "  " << Function << '\n';
      }
      ++NumStaleProfileFunctions;
      StaleSampleCount += SampleCount;
      ++NumAllStaleFunctions;
    }

    if (opts::ShowDensity) {
      uint64_t Size = Function.getSize();
      // In case of BOLT split functions registered in BAT, executed traces are
      // automatically attributed to the main fragment. Add up function sizes
      // for all fragments.
      if (IsHotParentOfBOLTSplitFunction)
        for (const BinaryFunction *Fragment : Function.getFragments())
          Size += Fragment->getSize();
      double Density = (double)1.0 * Function.getSampleCountInBytes() / Size;
      FuncDensityList.emplace_back(Density, SampleCount);
      LLVM_DEBUG(BC.outs() << Function << ": executed bytes "
                           << Function.getSampleCountInBytes() << ", size (b) "
                           << Size << ", density " << Density
                           << ", sample count " << SampleCount << '\n');
    }
  }
  BC.NumProfiledFuncs = ProfiledFunctions.size();
  BC.NumStaleProfileFuncs = NumStaleProfileFunctions;

  const size_t NumAllProfiledFunctions =
      ProfiledFunctions.size() + NumStaleProfileFunctions;
  BC.outs() << "BOLT-INFO: " << NumAllProfiledFunctions << " out of "
            << NumRegularFunctions << " functions in the binary ("
            << format("%.1f", NumAllProfiledFunctions /
                                  (float)NumRegularFunctions * 100.0f)
            << "%) have non-empty execution profile\n";
  if (NumNonSimpleProfiledFunctions) {
    BC.outs() << "BOLT-INFO: " << NumNonSimpleProfiledFunctions << " function"
              << (NumNonSimpleProfiledFunctions == 1 ? "" : "s")
              << " with profile could not be optimized\n";
  }
  if (NumAllStaleFunctions) {
    const float PctStale =
        NumAllStaleFunctions / (float)NumAllProfiledFunctions * 100.0f;
    const float PctStaleFuncsWithEqualBlockCount =
        (float)BC.Stats.NumStaleFuncsWithEqualBlockCount /
        NumAllStaleFunctions * 100.0f;
    const float PctStaleBlocksWithEqualIcount =
        (float)BC.Stats.NumStaleBlocksWithEqualIcount /
        BC.Stats.NumStaleBlocks * 100.0f;
    auto printErrorOrWarning = [&]() {
      if (PctStale > opts::StaleThreshold)
        BC.errs() << "BOLT-ERROR: ";
      else
        BC.errs() << "BOLT-WARNING: ";
    };
    printErrorOrWarning();
    BC.errs() << NumAllStaleFunctions
              << format(" (%.1f%% of all profiled)", PctStale) << " function"
              << (NumAllStaleFunctions == 1 ? "" : "s")
              << " have invalid (possibly stale) profile."
                 " Use -report-stale to see the list.\n";
    if (TotalSampleCount > 0) {
      printErrorOrWarning();
      BC.errs() << (StaleSampleCount + InferredSampleCount) << " out of "
                << TotalSampleCount << " samples in the binary ("
                << format("%.1f",
                          ((100.0f * (StaleSampleCount + InferredSampleCount)) /
                           TotalSampleCount))
                << "%) belong to functions with invalid"
                   " (possibly stale) profile.\n";
    }
    BC.outs() << "BOLT-INFO: " << BC.Stats.NumStaleFuncsWithEqualBlockCount
              << " stale function"
              << (BC.Stats.NumStaleFuncsWithEqualBlockCount == 1 ? "" : "s")
              << format(" (%.1f%% of all stale)",
                        PctStaleFuncsWithEqualBlockCount)
              << " have matching block count.\n";
    BC.outs() << "BOLT-INFO: " << BC.Stats.NumStaleBlocksWithEqualIcount
              << " stale block"
              << (BC.Stats.NumStaleBlocksWithEqualIcount == 1 ? "" : "s")
              << format(" (%.1f%% of all stale)", PctStaleBlocksWithEqualIcount)
              << " have matching icount.\n";
    if (PctStale > opts::StaleThreshold) {
      return createFatalBOLTError(
          Twine("BOLT-ERROR: stale functions exceed specified threshold of ") +
          Twine(opts::StaleThreshold.getValue()) + Twine("%. Exiting.\n"));
    }
  }
  if (NumInferredFunctions) {
    BC.outs() << format(
        "BOLT-INFO: inferred profile for %d (%.2f%% of profiled, "
        "%.2f%% of stale) functions responsible for %.2f%% samples"
        " (%zu out of %zu)\n",
        NumInferredFunctions,
        100.0 * NumInferredFunctions / NumAllProfiledFunctions,
        100.0 * NumInferredFunctions / NumAllStaleFunctions,
        100.0 * InferredSampleCount / TotalSampleCount, InferredSampleCount,
        TotalSampleCount);
    BC.outs() << format(
        "BOLT-INFO: inference found an exact match for %.2f%% of basic blocks"
        " (%zu out of %zu stale) responsible for %.2f%% samples"
        " (%zu out of %zu stale)\n",
        100.0 * BC.Stats.NumMatchedBlocks / BC.Stats.NumStaleBlocks,
        BC.Stats.NumMatchedBlocks, BC.Stats.NumStaleBlocks,
        100.0 * BC.Stats.MatchedSampleCount / BC.Stats.StaleSampleCount,
        BC.Stats.MatchedSampleCount, BC.Stats.StaleSampleCount);
  }

  if (const uint64_t NumUnusedObjects = BC.getNumUnusedProfiledObjects()) {
    BC.outs() << "BOLT-INFO: profile for " << NumUnusedObjects
              << " objects was ignored\n";
  }

  if (ProfiledFunctions.size() > 10) {
    if (opts::Verbosity >= 1) {
      BC.outs() << "BOLT-INFO: top called functions are:\n";
      llvm::sort(ProfiledFunctions,
                 [](const BinaryFunction *A, const BinaryFunction *B) {
                   return B->getExecutionCount() < A->getExecutionCount();
                 });
      auto SFI = ProfiledFunctions.begin();
      auto SFIend = ProfiledFunctions.end();
      for (unsigned I = 0u; I < opts::TopCalledLimit && SFI != SFIend;
           ++SFI, ++I)
        BC.outs() << "  " << **SFI << " : " << (*SFI)->getExecutionCount()
                  << '\n';
    }
  }

  if (!opts::PrintSortedBy.empty()) {
    std::vector<BinaryFunction *> Functions;
    std::map<const BinaryFunction *, DynoStats> Stats;

    for (auto &BFI : BC.getBinaryFunctions()) {
      BinaryFunction &BF = BFI.second;
      if (shouldOptimize(BF) && BF.hasValidProfile()) {
        Functions.push_back(&BF);
        Stats.emplace(&BF, getDynoStats(BF));
      }
    }

    const bool SortAll =
        llvm::is_contained(opts::PrintSortedBy, DynoStats::LAST_DYNO_STAT);

    const bool Ascending =
        opts::DynoStatsSortOrderOpt == opts::DynoStatsSortOrder::Ascending;

    std::function<bool(const DynoStats &, const DynoStats &)>
        DynoStatsComparator =
            SortAll ? [](const DynoStats &StatsA,
                         const DynoStats &StatsB) { return StatsA < StatsB; }
                    : [](const DynoStats &StatsA, const DynoStats &StatsB) {
                        return StatsA.lessThan(StatsB, opts::PrintSortedBy);
                      };

    llvm::stable_sort(Functions,
                      [Ascending, &Stats, DynoStatsComparator](
                          const BinaryFunction *A, const BinaryFunction *B) {
                        auto StatsItr = Stats.find(A);
                        assert(StatsItr != Stats.end());
                        const DynoStats &StatsA = StatsItr->second;

                        StatsItr = Stats.find(B);
                        assert(StatsItr != Stats.end());
                        const DynoStats &StatsB = StatsItr->second;

                        return Ascending ? DynoStatsComparator(StatsA, StatsB)
                                         : DynoStatsComparator(StatsB, StatsA);
                      });

    BC.outs() << "BOLT-INFO: top functions sorted by ";
    if (SortAll) {
      BC.outs() << "dyno stats";
    } else {
      BC.outs() << "(";
      bool PrintComma = false;
      for (const DynoStats::Category Category : opts::PrintSortedBy) {
        if (PrintComma)
          BC.outs() << ", ";
        BC.outs() << DynoStats::Description(Category);
        PrintComma = true;
      }
      BC.outs() << ")";
    }

    BC.outs() << " are:\n";
    auto SFI = Functions.begin();
    for (unsigned I = 0; I < 100 && SFI != Functions.end(); ++SFI, ++I) {
      const DynoStats Stats = getDynoStats(**SFI);
      BC.outs() << "  " << **SFI;
      if (!SortAll) {
        BC.outs() << " (";
        bool PrintComma = false;
        for (const DynoStats::Category Category : opts::PrintSortedBy) {
          if (PrintComma)
            BC.outs() << ", ";
          BC.outs() << dynoStatsOptName(Category) << "=" << Stats[Category];
          PrintComma = true;
        }
        BC.outs() << ")";
      }
      BC.outs() << "\n";
    }
  }

  if (!BC.TrappedFunctions.empty()) {
    BC.errs() << "BOLT-WARNING: " << BC.TrappedFunctions.size() << " function"
              << (BC.TrappedFunctions.size() > 1 ? "s" : "")
              << " will trap on entry. Use -trap-avx512=0 to disable"
                 " traps.";
    if (opts::Verbosity >= 1 || BC.TrappedFunctions.size() <= 5) {
      BC.errs() << '\n';
      for (const BinaryFunction *Function : BC.TrappedFunctions)
        BC.errs() << "  " << *Function << '\n';
    } else {
      BC.errs() << " Use -v=1 to see the list.\n";
    }
  }

  // Collect and print information about suboptimal code layout on input.
  if (opts::ReportBadLayout) {
    std::vector<BinaryFunction *> SuboptimalFuncs;
    for (auto &BFI : BC.getBinaryFunctions()) {
      BinaryFunction &BF = BFI.second;
      if (!BF.hasValidProfile())
        continue;

      const uint64_t HotThreshold =
          std::max<uint64_t>(BF.getKnownExecutionCount(), 1);
      bool HotSeen = false;
      for (const BinaryBasicBlock *BB : BF.getLayout().rblocks()) {
        if (!HotSeen && BB->getKnownExecutionCount() > HotThreshold) {
          HotSeen = true;
          continue;
        }
        if (HotSeen && BB->getKnownExecutionCount() == 0) {
          SuboptimalFuncs.push_back(&BF);
          break;
        }
      }
    }

    if (!SuboptimalFuncs.empty()) {
      llvm::sort(SuboptimalFuncs,
                 [](const BinaryFunction *A, const BinaryFunction *B) {
                   return A->getKnownExecutionCount() / A->getSize() >
                          B->getKnownExecutionCount() / B->getSize();
                 });

      BC.outs() << "BOLT-INFO: " << SuboptimalFuncs.size()
                << " functions have "
                   "cold code in the middle of hot code. Top functions are:\n";
      for (unsigned I = 0;
           I < std::min(static_cast<size_t>(opts::ReportBadLayout),
                        SuboptimalFuncs.size());
           ++I)
        SuboptimalFuncs[I]->print(BC.outs());
    }
  }

  if (NumUnknownControlFlowFunctions) {
    BC.outs() << "BOLT-INFO: " << NumUnknownControlFlowFunctions
              << " functions have instructions with unknown control flow";
    if (!opts::PrintUnknown)
      BC.outs() << ". Use -print-unknown to see the list.";
    BC.outs() << '\n';
  }

  if (opts::ShowDensity) {
    double Density = 0.0;
    // Sorted by the density in descending order.
    llvm::stable_sort(FuncDensityList,
                      [&](const std::pair<double, uint64_t> &A,
                          const std::pair<double, uint64_t> &B) {
                        if (A.first != B.first)
                          return A.first > B.first;
                        return A.second < B.second;
                      });

    uint64_t AccumulatedSamples = 0;
    uint32_t I = 0;
    assert(opts::ProfileDensityCutOffHot <= 1000000 &&
           "The cutoff value is greater than 1000000(100%)");
    while (AccumulatedSamples <
               TotalSampleCount *
                   static_cast<float>(opts::ProfileDensityCutOffHot) /
                   1000000 &&
           I < FuncDensityList.size()) {
      AccumulatedSamples += FuncDensityList[I].second;
      Density = FuncDensityList[I].first;
      I++;
    }
    if (Density == 0.0) {
      BC.errs() << "BOLT-WARNING: the output profile is empty or the "
                   "--profile-density-cutoff-hot option is "
                   "set too low. Please check your command.\n";
    } else if (Density < opts::ProfileDensityThreshold) {
      BC.errs()
          << "BOLT-WARNING: BOLT is estimated to optimize better with "
          << format("%.1f", opts::ProfileDensityThreshold / Density)
          << "x more samples. Please consider increasing sampling rate or "
             "profiling for longer duration to get more samples.\n";
    }

    BC.outs() << "BOLT-INFO: Functions with density >= "
              << format("%.1f", Density) << " account for "
              << format("%.2f",
                        static_cast<double>(opts::ProfileDensityCutOffHot) /
                            10000)
              << "% total sample counts.\n";
  }
  return Error::success();
}

Error InstructionLowering::runOnFunctions(BinaryContext &BC) {
  for (auto &BFI : BC.getBinaryFunctions())
    for (BinaryBasicBlock &BB : BFI.second)
      for (MCInst &Instruction : BB)
        BC.MIB->lowerTailCall(Instruction);
  return Error::success();
}

Error StripRepRet::runOnFunctions(BinaryContext &BC) {
  if (!BC.isX86())
    return Error::success();

  uint64_t NumPrefixesRemoved = 0;
  uint64_t NumBytesSaved = 0;
  for (auto &BFI : BC.getBinaryFunctions()) {
    for (BinaryBasicBlock &BB : BFI.second) {
      auto LastInstRIter = BB.getLastNonPseudo();
      if (LastInstRIter == BB.rend() || !BC.MIB->isReturn(*LastInstRIter) ||
          !BC.MIB->deleteREPPrefix(*LastInstRIter))
        continue;

      NumPrefixesRemoved += BB.getKnownExecutionCount();
      ++NumBytesSaved;
    }
  }

  if (NumBytesSaved)
    BC.outs() << "BOLT-INFO: removed " << NumBytesSaved
              << " 'repz' prefixes"
                 " with estimated execution count of "
              << NumPrefixesRemoved << " times.\n";
  return Error::success();
}

Error InlineMemcpy::runOnFunctions(BinaryContext &BC) {
  if (!BC.isX86())
    return Error::success();

  uint64_t NumInlined = 0;
  uint64_t NumInlinedDyno = 0;
  for (auto &BFI : BC.getBinaryFunctions()) {
    for (BinaryBasicBlock &BB : BFI.second) {
      for (auto II = BB.begin(); II != BB.end(); ++II) {
        MCInst &Inst = *II;

        if (!BC.MIB->isCall(Inst) || MCPlus::getNumPrimeOperands(Inst) != 1 ||
            !Inst.getOperand(0).isExpr())
          continue;

        const MCSymbol *CalleeSymbol = BC.MIB->getTargetSymbol(Inst);
        if (CalleeSymbol->getName() != "memcpy" &&
            CalleeSymbol->getName() != "memcpy@PLT" &&
            CalleeSymbol->getName() != "_memcpy8")
          continue;

        const bool IsMemcpy8 = (CalleeSymbol->getName() == "_memcpy8");
        const bool IsTailCall = BC.MIB->isTailCall(Inst);

        const InstructionListType NewCode =
            BC.MIB->createInlineMemcpy(IsMemcpy8);
        II = BB.replaceInstruction(II, NewCode);
        std::advance(II, NewCode.size() - 1);
        if (IsTailCall) {
          MCInst Return;
          BC.MIB->createReturn(Return);
          II = BB.insertInstruction(std::next(II), std::move(Return));
        }

        ++NumInlined;
        NumInlinedDyno += BB.getKnownExecutionCount();
      }
    }
  }

  if (NumInlined) {
    BC.outs() << "BOLT-INFO: inlined " << NumInlined << " memcpy() calls";
    if (NumInlinedDyno)
      BC.outs() << ". The calls were executed " << NumInlinedDyno
                << " times based on profile.";
    BC.outs() << '\n';
  }
  return Error::success();
}

bool SpecializeMemcpy1::shouldOptimize(const BinaryFunction &Function) const {
  if (!BinaryFunctionPass::shouldOptimize(Function))
    return false;

  for (const std::string &FunctionSpec : Spec) {
    StringRef FunctionName = StringRef(FunctionSpec).split(':').first;
    if (Function.hasNameRegex(FunctionName))
      return true;
  }

  return false;
}

std::set<size_t> SpecializeMemcpy1::getCallSitesToOptimize(
    const BinaryFunction &Function) const {
  StringRef SitesString;
  for (const std::string &FunctionSpec : Spec) {
    StringRef FunctionName;
    std::tie(FunctionName, SitesString) = StringRef(FunctionSpec).split(':');
    if (Function.hasNameRegex(FunctionName))
      break;
    SitesString = "";
  }

  std::set<size_t> Sites;
  SmallVector<StringRef, 4> SitesVec;
  SitesString.split(SitesVec, ':');
  for (StringRef SiteString : SitesVec) {
    if (SiteString.empty())
      continue;
    size_t Result;
    if (!SiteString.getAsInteger(10, Result))
      Sites.emplace(Result);
  }

  return Sites;
}

Error SpecializeMemcpy1::runOnFunctions(BinaryContext &BC) {
  if (!BC.isX86())
    return Error::success();

  uint64_t NumSpecialized = 0;
  uint64_t NumSpecializedDyno = 0;
  for (auto &BFI : BC.getBinaryFunctions()) {
    BinaryFunction &Function = BFI.second;
    if (!shouldOptimize(Function))
      continue;

    std::set<size_t> CallsToOptimize = getCallSitesToOptimize(Function);
    auto shouldOptimize = [&](size_t N) {
      return CallsToOptimize.empty() || CallsToOptimize.count(N);
    };

    std::vector<BinaryBasicBlock *> Blocks(Function.pbegin(), Function.pend());
    size_t CallSiteID = 0;
    for (BinaryBasicBlock *CurBB : Blocks) {
      for (auto II = CurBB->begin(); II != CurBB->end(); ++II) {
        MCInst &Inst = *II;

        if (!BC.MIB->isCall(Inst) || MCPlus::getNumPrimeOperands(Inst) != 1 ||
            !Inst.getOperand(0).isExpr())
          continue;

        const MCSymbol *CalleeSymbol = BC.MIB->getTargetSymbol(Inst);
        if (CalleeSymbol->getName() != "memcpy" &&
            CalleeSymbol->getName() != "memcpy@PLT")
          continue;

        if (BC.MIB->isTailCall(Inst))
          continue;

        ++CallSiteID;

        if (!shouldOptimize(CallSiteID))
          continue;

        // Create a copy of a call to memcpy(dest, src, size).
        MCInst MemcpyInstr = Inst;

        BinaryBasicBlock *OneByteMemcpyBB = CurBB->splitAt(II);

        BinaryBasicBlock *NextBB = nullptr;
        if (OneByteMemcpyBB->getNumNonPseudos() > 1) {
          NextBB = OneByteMemcpyBB->splitAt(OneByteMemcpyBB->begin());
          NextBB->eraseInstruction(NextBB->begin());
        } else {
          NextBB = OneByteMemcpyBB->getSuccessor();
          OneByteMemcpyBB->eraseInstruction(OneByteMemcpyBB->begin());
          assert(NextBB && "unexpected call to memcpy() with no return");
        }

        BinaryBasicBlock *MemcpyBB = Function.addBasicBlock();
        MemcpyBB->setOffset(CurBB->getInputOffset());
        InstructionListType CmpJCC =
            BC.MIB->createCmpJE(BC.MIB->getIntArgRegister(2), 1,
                                OneByteMemcpyBB->getLabel(), BC.Ctx.get());
        CurBB->addInstructions(CmpJCC);
        CurBB->addSuccessor(MemcpyBB);

        MemcpyBB->addInstruction(std::move(MemcpyInstr));
        MemcpyBB->addSuccessor(NextBB);
        MemcpyBB->setCFIState(NextBB->getCFIState());
        MemcpyBB->setExecutionCount(0);

        // To prevent the actual call from being moved to cold, we set its
        // execution count to 1.
        if (CurBB->getKnownExecutionCount() > 0)
          MemcpyBB->setExecutionCount(1);

        InstructionListType OneByteMemcpy = BC.MIB->createOneByteMemcpy();
        OneByteMemcpyBB->addInstructions(OneByteMemcpy);

        ++NumSpecialized;
        NumSpecializedDyno += CurBB->getKnownExecutionCount();

        CurBB = NextBB;

        // Note: we don't expect the next instruction to be a call to memcpy.
        II = CurBB->begin();
      }
    }
  }

  if (NumSpecialized) {
    BC.outs() << "BOLT-INFO: specialized " << NumSpecialized
              << " memcpy() call sites for size 1";
    if (NumSpecializedDyno)
      BC.outs() << ". The calls were executed " << NumSpecializedDyno
                << " times based on profile.";
    BC.outs() << '\n';
  }
  return Error::success();
}

StringMap<BasicBlockSimilarityMetaData *> BBCommonMap;
StringMap<const BinaryBasicBlock *> BBSignatureMap;

Error FindSimBB::runOnFunctions(BinaryContext &BC) {
  if (!BC.isX86())
    return Error::success();
  outs() << "BOLT-INFO: Running BB Similarity Finder\n";  
  bool do_once = false;


  size_t TotalBlocks = 0;
  uint64_t TotalBlockSize = 0;
  for (auto &BFI : BC.getBinaryFunctions()) {
    if (do_once) break;
    BinaryFunction &Function = BFI.second;
    std::vector<BinaryBasicBlock *> Blocks(Function.pbegin(), Function.pend());
    for (BinaryBasicBlock *CurBB : Blocks) {
      // outs() << "Dumping a basic block:\n";
      // CurBB->dump();
      std::string block_hash = CurBB->getBlockHash();
      if (block_hash.compare("empty") == 0)
        continue;
      if (CurBB->getOriginalSize() >= 1000000)//UINT32_MAX)
        continue;
      TotalBlocks++;
      TotalBlockSize += CurBB->getOriginalSize();
      if (!BBSignatureMap.contains(block_hash)) {
        BasicBlockSimilarityMetaData *val = new BasicBlockSimilarityMetaData;
        val->count = 0;
        BBSignatureMap[block_hash] = CurBB;
        BBCommonMap[block_hash] = val;
      }
      else {
        // outs() << "Found a hit :\n";
        // CurBB->dump();        
      }
      BBCommonMap[block_hash]->count++;
      BBCommonMap[block_hash]->function_vec.push_back(&Function);
      // outs() << "SimBB Function: " << Function.getPrintName() << ", Section: " << Function.getOriginSection()->getName() << "\n";
      BBCommonMap[block_hash]->block_vec.push_back(CurBB);
      BBCommonMap[block_hash]->block_hash = block_hash;      
      BBCommonMap[block_hash]->original_size = CurBB->getOriginalSize();
      BBCommonMap[block_hash]->RetOrIndJump = BC.MIB->isReturn(CurBB->back()) || BC.MIB->isIndirectBranch(CurBB->back()) || BC.MIB->isReturnEndingWithCFI(const_cast<BinaryBasicBlock *>(CurBB)) || BC.MIB->isIndJmpEndingWithCFI(const_cast<BinaryBasicBlock *>(CurBB));
      
      /* Add Threshold also here*/
      if (BBCommonMap[block_hash]->RetOrIndJump)
      {
        BBCommonMap[block_hash]->Threshold = 5; // Threshold for jmp
      }

      else 
      {
        /*Check if it has an access to %rsp or %rbp*/
        if (BC.MIB->hasStackFrameReg(const_cast<BinaryBasicBlock *>(CurBB)))
        {
          BBCommonMap[block_hash]->Threshold = 25; // Threshold for push %r11, .... jmp *0x10(%rbp)
          StackAdjustedFuncs.push_back(Function.getPrintName());
        }

        else 
        {
          BBCommonMap[block_hash]->Threshold = 6; // Threshold for Call & Return
        }
      }

      std::string hexval;
      llvm::raw_string_ostream Str(hexval);
      Str.write_hex(CurBB->getInputOffset());
      Str.flush();
      BBCommonMap[block_hash]->offset_vec.push_back(hexval);
    }
  } 

  std::vector<const BasicBlockSimilarityMetaData *> sorted_sim_vec;
  for (auto II = BBCommonMap.begin(); II != BBCommonMap.end(); ++II) {
    sorted_sim_vec.push_back(II->second);    
  }
  std::sort(sorted_sim_vec.begin(), sorted_sim_vec.end(), [](auto A, auto B) {
    // return (A->count * A->original_size) > (B->count * B->original_size);
    return A->original_size > B->original_size;
  });
  

  // Dump the String Map when the vector is of size > 1:
  size_t RedundantBlocks = 0;
  uint64_t RedundantBlockSize = 0;
  size_t RetOrIndirectJmpBlocks = 0;
  uint64_t RetOrIndirectJmpBlocksSize = 0;
  uint64_t ExpectedSavings = 0;
  // for (auto II = BBCommonMap.begin(); II != BBCommonMap.end(); ++II) {
  u_int64_t CSVLastSize = sorted_sim_vec[0]->original_size;
  u_int64_t CSVSizeCount = 0;
  for (const BasicBlockSimilarityMetaData *val : sorted_sim_vec) {
    const uint32_t SIZE_THRESHOLD = 15; // Change this according to the type of BasicBlocks used
    if (val->original_size < val->Threshold)
      continue;
    if (val->count == 1)
      continue;
    if (val->RetOrIndJump) {
      // outs() << "BOLT-INFO: Ret or Indirect Jump : " <<  val->count - 1 << " blocks \n";
      // BBSignatureMap[val->block_hash]->dump();
      RetOrIndirectJmpBlocks += val->count - 1;
      RetOrIndirectJmpBlocksSize += ((val->count -1) * val->original_size);
    }

    ExpectedSavings += ((val->count-1) * val->original_size) - (val->count*val->Threshold);

    RedundantBlocks += val->count - 1;
    RedundantBlockSize += ((val->count -1) * val->original_size); // It should account for the threshold
    if (val->original_size == CSVLastSize) {
      CSVSizeCount += val->count - 1;
    } else {
      // outs() << "BOLT-CSV: " << CSVLastSize << "," << CSVSizeCount << "\n";
      CSVLastSize = val->original_size;
      CSVSizeCount = val->count - 1;
    }
    // outs() << "BOLT-INFO: Found " << val->count - 1  << " redundant basic blocks for " << val->block_hash;
    // outs() << " with size : " << val->original_size <<" bytes\n";
    // outs() << "******************";
    // BBSignatureMap[val->block_hash]->dump();
    // outs() << "******************";
    // outs() << "\nListing all functions where the block was found :\n";
    // auto OffsetI = val->offset_vec.begin();
    // for (auto BF : val->function_vec) {
      // outs() << BF->getPrintName() << " at offset : " << *OffsetI << "\n";
      // ++OffsetI;      
    // }
    // outs() << "\n\n";
  }
  // outs() << "BOLT-CSV: " << CSVLastSize << "," << CSVSizeCount << "\n";
  outs() << "BOLT-INFO: Redundant Blocks = " << RedundantBlocks << " / " << TotalBlocks<< "\n";
  outs() << "BOLT-INFO: Redundant Block Size = " << RedundantBlockSize << " / " << TotalBlockSize << "\n";
  outs() << "BOLT-INFO: Ret/Indirect Jmp Blocks = " << 
            RetOrIndirectJmpBlocks << " / " << TotalBlocks << "\n";
  outs() << "BOLT-INFO: Ret/Indirect Jmp Blocks Size = " <<
            RetOrIndirectJmpBlocksSize << " / " << TotalBlockSize << "\n";
  
  outs() << "BOLT-INFO: Expected Savings in Size = " << ExpectedSavings << "\n";

  return Error::success();
}

Error AdjustStack::runOnFunctions(BinaryContext &BC) {
  if (!BC.isX86())
    return Error::success();

  int matchPrologueEpilogue;
  
  bool todoPrologue = false;
  bool todoEpilogue = false;

  int adjustedFuncs = 0;

  for (auto &BFI : BC.getBinaryFunctions()) {

    BinaryFunction &Function = BFI.second;

    std::string funcTobeModified = Function.getPrintName();
    auto it = std::find(StackAdjustedFuncs.begin(), StackAdjustedFuncs.end(), funcTobeModified);

    if (it==StackAdjustedFuncs.end())
    {
      continue;
    }

    std::vector<BinaryBasicBlock *> Blocks(Function.pbegin(), Function.pend());

    matchPrologueEpilogue = 0;

    todoPrologue = false;
    todoEpilogue = false;
    
    for (BinaryBasicBlock *CurBB : Blocks) 
    {

      if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
      {
          matchPrologueEpilogue += 1;
          todoPrologue = true;
        
      }

      if (BC.MIB->isEpilogue(const_cast<BinaryBasicBlock *>(CurBB)))
      {          
        todoEpilogue = true;
        matchPrologueEpilogue -= 1;
      }
    }

    if (matchPrologueEpilogue == 0 && todoPrologue && todoEpilogue)
    {

      if (Function.getPrintName() == "_ZN11xalanc_1_1014DOMSupportInitD2Ev(*2)" ||
        Function.getPrintName() == "_ZN11xalanc_1_1033StylesheetExecutionContextDefault19pushCurrentTemplateEPKNS_12ElemTemplateE" ||
        Function.getPrintName() == "_ZN11xalanc_1_1014XMLSupportInitD2Ev(*2)" ||
        Function.getPrintName() == "_ZN11xalanc_1_109XPathInitD1Ev(*2)" ||
        Function.getPrintName() == "_ZN11xalanc_1_108XSLTInitD2Ev(*2)" ||
        Function.getPrintName() == "_ZN11xalanc_1_1014ArenaAllocatorINS_23XalanSourceTreeElementAENS_10ArenaBlockIS1_mEEED0Ev" ||
        Function.getPrintName() == "_ZN11xalanc_1_1019XalanSourceTreeInitD1Ev(*2)")
      {
        outs() << "Skipping Function: " << Function.getPrintName() << "\n";
        continue;
      }

      OutlineStackAdjustedFuncs.push_back(Function.getPrintName());

      adjustedFuncs += 1;

      for (BinaryBasicBlock *CurBB : Blocks) 
      {
          if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
          {
              std::string oldHash = CurBB->getBlockHash();

              BC.MIB->setStackPointerIncrement(const_cast<BinaryBasicBlock *>(CurBB));

              BC.MIB->updateStackFrameRegOffset(const_cast<BinaryBasicBlock *>(CurBB));

              std::string newHash = CurBB->getBlockHash();

              BBHashMap[newHash] = oldHash;
          }

          if(BC.MIB->isEpilogue(const_cast<BinaryBasicBlock *>(CurBB)))
          {
              std::string oldHash = CurBB->getBlockHash();

              BC.MIB->setStackPointerDecrement(const_cast<BinaryBasicBlock *>(CurBB));

              if (!BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
              {
                BC.MIB->updateStackFrameRegOffset(const_cast<BinaryBasicBlock *>(CurBB));
              }

              std::string newHash = CurBB->getBlockHash();

              BBHashMap[newHash] = oldHash;
          }

          if (!BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)) && !BC.MIB->isEpilogue(const_cast<BinaryBasicBlock *>(CurBB)))
          {
            std::string oldHash = CurBB->getBlockHash();

            BC.MIB->updateStackFrameRegOffset(const_cast<BinaryBasicBlock *>(CurBB));

            std::string newHash = CurBB->getBlockHash();

            BBHashMap[newHash] = oldHash;

          }
      }
    }
  }

  outs() << "Adjusted Stack in " << adjustedFuncs << " Functions\n";

  return Error::success();
}

bool OutlineSimBB::Optimization() const {
  
  for (const std::string &FunctionSpec : Spec) {
    StringRef OptionName = StringRef(FunctionSpec).split(':').first;

    if (OptionName.str() == "false")
    {
      return false;
    }

    else if (OptionName.str() == "true")
    {
      return true;
    }
  }

  return false;
}

BinaryBasicBlock *JmpThreadretBB = nullptr;

Error OutlineSimBB::globalizeSymbolsBeforeOutline(BinaryContext &BC, BinaryFunction *Function, std::vector<BinaryBasicBlock *> Blocks, int OutlineBlockCounter, std::string blockHash) const
{
  std::unordered_map<const MCSymbol *, MCSymbol *> RenamedLabels;

  MCContext &Ctx = *BC.Ctx.get();

  int temp = 0;
  for (auto *BB : Blocks) 
  {
    for (auto *Succ : BB->successors()) 
    {

      std::string OldLabelName = Succ->getLabel()->getName().str();

      if (OldLabelName.find("SuccBB_") == std::string::npos) 
      {

        temp+=1;

        std::string SuccBBName = "SuccBB_"+blockHash+"_"+std::to_string(temp)+"_"+std::to_string(OutlineBlockCounter);

        std::replace(SuccBBName.begin(), SuccBBName.end(), '.', '_');
        std::replace(SuccBBName.begin(), SuccBBName.end(), '/', '_');
        std::replace(SuccBBName.begin(), SuccBBName.end(), '+', '_');

        MCSymbol *SuccBBLabel = BC.getOrCreateUndefinedGlobalSymbol(SuccBBName);

        RenamedLabels[Succ->getLabel()] = SuccBBLabel;

        Succ->setLabel(SuccBBLabel);
      }


    }

  }

  for (auto *BB : Blocks) 
  {
    for (auto &Inst : BB->instructions()) 
    {
      for (size_t OpIdx = 0; OpIdx < Inst.getNumOperands(); ++OpIdx) {
          if (Inst.getOperand(OpIdx).isExpr()) {
              const MCExpr *Expr = Inst.getOperand(OpIdx).getExpr();
              if (auto *SymbolRef = dyn_cast<MCSymbolRefExpr>(Expr)) {
                  const MCSymbol *OldLabel = &SymbolRef->getSymbol();
                  
                  if (RenamedLabels.find(OldLabel) != RenamedLabels.end()) {
                      MCSymbol *NewLabel = RenamedLabels[OldLabel];

                      // BC.MIB->replaceBranchTarget(Inst, NewLabel, &Ctx);
                      
                      const MCExpr *NewExpr = MCSymbolRefExpr::create(NewLabel, SymbolRef->getKind(), Ctx);
                      Inst.getOperand(OpIdx) = MCOperand::createExpr(NewExpr);
                  }
              }
          }
      }
    }

    if (BB->hasJumpTable())
    {
      BB->globalizeJumpTableSymbols(RenamedLabels);
    }
  }

  return Error::success();
}

Error OutlineSimBB::globalizeSymbolsAfterOutline(BinaryContext &BC, BinaryFunction *Function, std::vector<BinaryBasicBlock *> Blocks, int OutlineBlockCounter, std::string blockHash) const
{
  std::unordered_map<const MCSymbol *, MCSymbol *> RenamedLabels;

  MCContext &Ctx = *BC.Ctx.get();

  int temp = 0;
  for (auto *BB : Blocks) 
  {
    for (auto *Succ : BB->successors()) 
    {

      std::string OldLabelName = Succ->getLabel()->getName().str();

      if (OldLabelName.find("SuccBB_") == std::string::npos || OldLabelName.find("outline_") == std::string::npos || OldLabelName.find("ret_") == std::string::npos) 
      {

        temp+=1;

        std::string SuccBBName = "SuccBB_"+blockHash+"_"+std::to_string(temp)+"_"+std::to_string(OutlineBlockCounter);

        MCSymbol *SuccBBLabel = BC.getOrCreateUndefinedGlobalSymbol(SuccBBName);

        RenamedLabels[Succ->getLabel()] = SuccBBLabel;

        Succ->setLabel(SuccBBLabel);
      }
    }
  }

  for (auto *BB : Blocks) 
  {
    for (auto &Inst : BB->instructions()) 
    {
      for (size_t OpIdx = 0; OpIdx < Inst.getNumOperands(); ++OpIdx) {
          if (Inst.getOperand(OpIdx).isExpr()) {
              const MCExpr *Expr = Inst.getOperand(OpIdx).getExpr();
              if (auto *SymbolRef = dyn_cast<MCSymbolRefExpr>(Expr)) {
                  const MCSymbol *OldLabel = &SymbolRef->getSymbol();
                  
                  if (RenamedLabels.find(OldLabel) != RenamedLabels.end()) {
                      MCSymbol *NewLabel = RenamedLabels[OldLabel];
                 
                      const MCExpr *NewExpr = MCSymbolRefExpr::create(NewLabel, SymbolRef->getKind(), Ctx);
                      Inst.getOperand(OpIdx) = MCOperand::createExpr(NewExpr);
                  }
              }
          }
      }
    }

    if (BB->hasJumpTable())
    {
      BB->globalizeJumpTableSymbols(RenamedLabels);
    }
  }

  return Error::success();
}

bool OutlineSimBB::isOutlineAbleAfterSplitting(BinaryContext &BC, BinaryBasicBlock *CurBB, BinaryBasicBlock::iterator *SplitII, int SIZE_THRESHOLD, bool jumpThreading) const
{
    int NumInst = 0;

    bool found = false;

    for (auto II = CurBB->rbegin(); II != CurBB->rend(); ++II) 
    {
        MCInst &Inst = *II;

        if (BC.MIB->SplitJmpBB(Inst))
        {
          found = true;
          continue;
        }

        if (found)
        {
          found = false;
          *SplitII = II.base();
        }

        NumInst+=1;
    }

    if (NumInst < 1)
      return false;

    uint64_t MasterBBSize = 0;

    if (jumpThreading)
    {
        for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) 
        {
            MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
        }

        if (MasterBBSize < SIZE_THRESHOLD)
        {
            outs() << "Skipping Size: " << MasterBBSize << " Threshold: " << SIZE_THRESHOLD << "\n";
            return false;
        }

        outs() << "Size matches: " << MasterBBSize << " Threshold: " << SIZE_THRESHOLD << "\n";
        return true;
    }

    for (auto Itr = CurBB->begin(); Itr != *SplitII; ++Itr) 
    {
        MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
    }

    if (MasterBBSize < SIZE_THRESHOLD)
    {
        return false;
    }

    return true;
}

static int tempCFIret = 0;
static int tempCFIindJmp = 0;

Error OutlineSimBB::outlineRetIndJmp(std::vector<BinaryFunction *> Functions, std::string blockHash, int &RedundantBlockCount, int &TotalBlocksOutlined) const
{

  bool first_block_to_be_outlined = true;

  bool func_to_be_folded = false;

  bool hasRetqIndJmp = true;

  BinaryContext &BC1 = Functions[0]->getBinaryContext();

  if (BBSignatureMap[blockHash]->pred_begin() == BBSignatureMap[blockHash]->pred_end() && BBSignatureMap[blockHash]->succ_begin() == BBSignatureMap[blockHash]->succ_end())
  {
      func_to_be_folded = true;
      hasRetqIndJmp = false;
  }
  
  if(BC1.MIB->isEndingWithIndirectJump(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])))
  { 

    const MCInst &LastInst = BBSignatureMap[blockHash]->back();

    if (BC1.MIB->isTailCall(LastInst))
    {
      hasRetqIndJmp = true;
    }

    else 
    {
      hasRetqIndJmp = false;
      return Error::success();
    }
  }

  if (BC1.MIB->isReturnEndingWithCFI(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])))
  {

    tempCFIret += 1;

    if (tempCFIret == 266 || tempCFIret == 302 || tempCFIret == 303 || tempCFIret == 401 || tempCFIret == 402 || tempCFIret == 404 || tempCFIret == 405)
      return Error::success();

    outs() << "ReturnEndingWithCFI: " << tempCFIret << "\n";
  }

  if (BC1.MIB->isIndJmpEndingWithCFI(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])))
  {

    

    if (BC1.MIB->isCFITailCall(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])))
    {
      hasRetqIndJmp = true;

      tempCFIindJmp += 1;

      if (tempCFIindJmp == 110)
        return Error::success();

      // if (tempCFIindJmp > 111)
      //   return Error::success();

      outs() << "IndJmpEndingWithCFI: " << tempCFIindJmp << "\n";
    }

    else 
    {
      hasRetqIndJmp = false;
      return Error::success();
    }

  }

  static int OutlineBlockCounter = 0;

  BinaryFunction *OutlinedFunc;

  bool stackAdjusted = false;

  bool MasterStackAdjusted = false;

  for (auto Function: Functions)
  {
      stackAdjusted = false;

      BinaryContext &BC = Function->getBinaryContext();

      MCContext &Ctx = *BC.Ctx.get();

      auto it = std::find(OutlineStackAdjustedFuncs.begin(), OutlineStackAdjustedFuncs.end(), Function->getPrintName());

      if (it != OutlineStackAdjustedFuncs.end())
      {
        stackAdjusted = true;

        if (first_block_to_be_outlined)
          MasterStackAdjusted = true;
      }

      std::vector<BinaryBasicBlock *> Blocks(Function->pbegin(), Function->pend());

      for (BinaryBasicBlock *CurBB : Blocks) 
      {
          if (CurBB->empty())
            continue;

          std::string block_hash = CurBB->getBlockHash();

          if (MasterStackAdjusted)
            block_hash = BBHashMap[block_hash];

          if(block_hash.compare(blockHash) == 0)
          {
              if (func_to_be_folded)
              {
                  if (first_block_to_be_outlined)
                  {

                      RedundantBlockCount += 1;

                      OutlineBlockCounter += 1;

                      outs() << "Master Function: " << Function->getPrintName() << "blockHash: " << block_hash << " v/s " << blockHash << "\n";

                      // std::string OutlineBBName = Function->getPrintName();

                      // MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                      // Function->setLabel(OutlineBBLabel);
                      
                      OutlinedFunc = Function;

                      first_block_to_be_outlined = false;

                      CurBB->dump();

                      outs() << "\n****\n";

                  }

                  else 
                  {
                      TotalBlocksOutlined += 1;

                      OutlineBlockCounter += 1;

                      outs() << "Outlined Function: " << Function->getPrintName() << "blockHash: " << block_hash << " v/s " << blockHash << "\n";

                      CurBB->dump();

                      outs() << "\n****\n";

                      std::string OutlineBBName = OutlinedFunc->getPrintName();

                      size_t pos = OutlineBBName.find('(');
    
                      
                      if (pos != std::string::npos) {
                          OutlineBBName = OutlineBBName.substr(0, pos);
                      }

                      MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                      CurBB->clear();

                      MCInst MyCallInstr;
                      BC.MIB->createCall(MyCallInstr, OutlineBBLabel, &*BC.Ctx);
                      CurBB->addInstruction(MyCallInstr);

                      MCInst RetInstr;
                      BC.MIB->createReturn(RetInstr);
                      CurBB->addInstruction(RetInstr);

                      CurBB->dump();

                      outs() << "\n******\n";
                  }
              }

              else if (hasRetqIndJmp)
              {
                  if (first_block_to_be_outlined)
                  {

                      RedundantBlockCount += 1;

                      OutlineBlockCounter += 1;

                      globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                      // globalizeSymbolsBeforeOutline(BC, Blocks, OutlineBlockCounter, blockHash);

                      outs() << "Master Function: " << Function->getPrintName() << " blockHash: " << block_hash << " v/s " << blockHash << "\n";

                      CurBB->dump();

                      outs() << "\n****\n";

                      OutlinedFunc = Function;

                      MCSymbol *OldLabel = CurBB->getLabel();

                      std::string OutlineBBName = "outline_"+blockHash;

                      MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                      auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                      OutlineBB->setOffset(CurBB->getInputOffset());

                      for (auto II = CurBB->begin(); II != CurBB->end(); ++II) {
                          MCInst &Inst = *II;
                          OutlineBB->addInstruction(Inst);
                      }

                      // auto NextBB = CurBB->getSuccessor();
                      OutlineBB->setCFIState(CurBB->getCFIState());
                      OutlineBB->setExecutionCount(CurBB->getExecutionCount());

                      for (BinaryBasicBlock *BB : Blocks) {

                        if (BB->succ_begin()!=BB->succ_end())
                        {
                          std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                          for (BinaryBasicBlock *Succ : Successors) {

                              if (Succ->getLabel() == OldLabel)
                              {
                                BB->replaceSuccessor(Succ, OutlineBB, 0,0);
                              }
                          }
                        }
                        
                      }

                      if (CurBB->succ_begin() != CurBB->succ_end())
                        CurBB->moveAllSuccessorsTo(OutlineBB);

                      CurBB->clear();

                      outs() << "OutlineBB->dump()\n";

                      OutlineBB->dump();

                      outs() << "\n*****\n";

                      first_block_to_be_outlined = false;

                  }

                  else 
                  {

                      TotalBlocksOutlined += 1;

                      OutlineBlockCounter += 1;

                      globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                      std::string OutlineBBName = "outline_"+blockHash;

                      MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                      auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                      if (!BC.MIB->checkCFIEqual(const_cast<BinaryBasicBlock *>(CurBB), const_cast<BinaryBasicBlock *>(OutlineBB)))
                        continue;

                      outs() << "Outlined Function: " << Function->getPrintName() << " blockHash: " << block_hash << " v/s " << blockHash << "\n";

                      CurBB->dump();

                      outs() << "\n****\n";

                      MCSymbol *OldLabel = CurBB->getLabel();

                      

                      std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                      MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                      auto NewBB = Function->addBasicBlock(NewBBLabel); 

                      NewBB->setOffset(CurBB->getInputOffset());

                      for (BinaryBasicBlock *BB : Blocks) {

                        if (BB->succ_begin()!=BB->succ_end())
                        {
                          std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                          for (BinaryBasicBlock *Succ : Successors) {

                              if (Succ->getLabel() == OldLabel)
                              {
                                BB->replaceSuccessor(Succ, NewBB, 0, 0);
                              }
                          }
                        }
                      }

                      InstructionListType NewBBToOutlineBB = BC.MIB->createRedirectToOutliner(OutlineBBLabel, &Ctx);

                      NewBB->addInstructions(NewBBToOutlineBB);

                      NewBB->addSuccessor(OutlineBB);
                      NewBB->setCFIState(OutlineBB->getCFIState());
                      NewBB->setExecutionCount(0);

                      NewBB->dump();

                      OutlineBB->dump();

                      CurBB->clear();

                      outs() << "NewBB->dump()\n";

                      NewBB->dump();

                      outs() << "\n*****\n";

                      outs() << "OutlineBB->dump()\n";

                      OutlineBB->dump();

                      outs() << "\n*****\n";
                  }
              }                
          }
      }
  }

  return Error::success();
}

static int doing_trying_once = 0;

static int count_else_jmp_r11_rbp = 0;

static int count_thres_6_condJmps = 0;

static int count_thres_25_condJmps = 0;

static int remainBigChunk = 0;

static int cfiremain = 0;

static int count_jmp_thread = 0;

Error OutlineSimBB::outlineAnyOtherBB(std::vector<BinaryFunction *> Functions, std::string blockHash, int &RedundantBlockCount, int &TotalBlocksOutlined, int SIZE_THRESHOLD, int &countRemaining) const
{

  BinaryContext &BC1 = Functions[0]->getBinaryContext();

  bool first_block_to_be_outlined = true;

  bool func_to_be_folded = false;

  bool no_rsp_rbp = false;

  bool jmp_r11_rbp = false;

  if (BC1.MIB->isJumpThread(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])) && SIZE_THRESHOLD == 25)
  {
      // return Error::success();

      count_jmp_thread += 1;

      if (count_jmp_thread == 53) // count_jmp_thread == 44 ||
      {
        outs() << "JUMPTHREAD IGNORED: " << count_jmp_thread << "\n";
        return Error::success();
      }
        

      if (count_jmp_thread > 45)
        return Error::success();

      outs() << "Outline JumpThread: " << count_jmp_thread << "\n";

      // if (BC1.MIB->hasCFI(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])))
      // {
      //   return Error::success();
      // }

      static int OutlineBlockCounter = 0;

      BinaryFunction *OutlinedFunc;

      for (auto Function: Functions)
      {
          BinaryContext &BC = Function->getBinaryContext();

          MCContext &Ctx = *BC.Ctx.get();

          auto it = std::find(OutlineStackAdjustedFuncs.begin(), OutlineStackAdjustedFuncs.end(), Function->getPrintName());

          if (it == OutlineStackAdjustedFuncs.end())
          {
            // outs() << "Skipping Because of Stack Not Adjusted: \n";
            return Error::success();
          }

          std::vector<BinaryBasicBlock *> Blocks(Function->pbegin(), Function->pend());

          for (BinaryBasicBlock *CurBB : Blocks) 
          {
              if (CurBB->empty())
                continue;

              std::string block_hash = CurBB->getBlockHash();

              block_hash = BBHashMap[block_hash];

              if(block_hash.compare(blockHash) == 0)
              {
                  if (first_block_to_be_outlined)
                  {
                      if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
                      {          

                          return Error::success();          

                          outs() << "Master Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JUMPTHREAD_R11_RBP_Prologue: " << count_else_jmp_r11_rbp << ", SIZE_THRESHOLD: " << SIZE_THRESHOLD << "\n";

                          CurBB->dump();

                          outs() << "\n******\n";

                          bool found = false;

                          BinaryBasicBlock *PrologueBB = nullptr;
                          for (auto II = CurBB->begin(); II != CurBB->end(); ++II) 
                          {
                              MCInst &Inst = *II;

                              if (found)
                              {
                                  PrologueBB = CurBB->splitAt(II);
                                  break;
                              }

                              if (BC.MIB->SplitPrologue(Inst))
                              { 
                                found = true;
                              }
                          }

                          /* CHECK if Splitting Prologue Still Works*/

                          BinaryBasicBlock::iterator SplitII;

                          if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(PrologueBB), &SplitII, SIZE_THRESHOLD, true))
                            return Error::success();

                          count_thres_25_condJmps += 1;

                          outs() << "JMPTHREAD_condJmps: " << count_thres_25_condJmps << "\n";

                          OutlineBlockCounter += 1;

                          globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                          RedundantBlockCount += 1;

                          BinaryBasicBlock *MasterBB = nullptr;

                          MasterBB = PrologueBB->splitAt(SplitII);

                          outs() << "SIZEMEETS JMPCONDUNCOND:\n";

                          PrologueBB->dump();

                          outs() << "\n******\n";

                          MasterBB->dump();

                          outs() << "\n******\n";

                          OutlinedFunc = Function;

                          std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                          MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                          std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          std::replace(retBBName.begin(), retBBName.end(), '.', '_');
                          std::replace(retBBName.begin(), retBBName.end(), '/', '_');
                          std::replace(retBBName.begin(), retBBName.end(), '+', '_');

                          MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                          MCSymbol *OldLabel = CurBB->getLabel();

                          CurBB->setLabel(NewBBLabel);

                          for (BinaryBasicBlock *BB : Blocks) 
                          {
                              if (BB->succ_begin()!=BB->succ_end())
                              {
                                std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                for (BinaryBasicBlock *Succ : Successors) {

                                    if (Succ->getLabel() == OldLabel)
                                    {
                                      BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                    }
                                }
                              }
                          }
                          
                          MasterBB->setLabel(retBBLabel);

                          std::string OutlineBBName = "outline_"+blockHash;

                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                          auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                          std::vector<MCInst> TempInsts(PrologueBB->instructions().begin(), PrologueBB->instructions().end());

                          for (size_t i = 0; i < TempInsts.size(); ++i) 
                          {
                            OutlineBB->addInstruction(TempInsts[i]);
                          }

                          InstructionListType OutlineBBToNewBB = BC.MIB->createOutlinerToRedirectAnyOtherBB(16);
                          OutlineBB->addInstructions(OutlineBBToNewBB);

                          PrologueBB->clear();

                          OutlineBB->setLabel(OutlineBBLabel);
                          OutlineBB->addSuccessor(MasterBB);
                          OutlineBB->setCFIState(MasterBB->getCFIState());
                          OutlineBB->setExecutionCount(0);

                          InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                          CurBB->addInstructions(NewBBToOutliner);
                          CurBB->removeAllSuccessors();
                          CurBB->addSuccessor(OutlineBB);

                          uint64_t CurBBSize = 0;

                          for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                              CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                          OutlineBB->setOffset(CurBB->getEndOffset());

                          uint64_t OutlineBBSize = 0;
                          for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                              OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          OutlineBB->setEndOffset(OutlineBB->getInputOffset() + OutlineBBSize);

                          MasterBB->setOffset(OutlineBB->getEndOffset());

                          uint64_t MasterBBSize = 0;
                          for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                              MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n*****\n";

                          outs() << "retBB->dump()\n";

                          MasterBB->dump();

                          outs() << "\n*****\n";

                          first_block_to_be_outlined = false;
                      }

                      else 
                      {
                          outs() << "Master Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JUMPTHREAD_R11_RBP: " << remainBigChunk << "\n";

                          remainBigChunk += 1;

                          CurBB->dump();

                          outs() << "\n******\n";
                    
                          BinaryBasicBlock::iterator SplitII;

                          if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(CurBB), &SplitII, SIZE_THRESHOLD, true))
                            return Error::success();

                          count_thres_25_condJmps += 1;

                          outs() << "Thres_25_condJmps: " << count_thres_25_condJmps << "\n";

                          OutlineBlockCounter += 1;

                          globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                          RedundantBlockCount += 1;

                          auto retBB = CurBB->getSuccessor();

                          MCSymbol *retBBLabel = retBB->getLabel();

                          outs() << "SIZEMEETS JMPCONDUNCOND: JMP_R11_RBP SIZE: Label: " << retBB->getLabel()->getName().str() << "\n";

                          CurBB->dump();

                          outs() << "\n******\n";

                          // MasterBB->dump();

                          // outs() << "\n******\n";

                          OutlinedFunc = Function;

                          std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                          MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                          MCSymbol *OldLabel = CurBB->getLabel();

                          CurBB->setLabel(NewBBLabel);

                          for (BinaryBasicBlock *BB : Blocks) 
                          {
                              if (BB->succ_begin()!=BB->succ_end())
                              {
                                std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                for (BinaryBasicBlock *Succ : Successors) {

                                    if (Succ->getLabel() == OldLabel)
                                    {
                                      BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                    }
                                }
                              }
                          }
                          
                          // MasterBB->setLabel(retBBLabel);

                          std::string OutlineBBName = "outline_"+blockHash;

                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);
                          auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                          std::vector<MCInst> TempInsts(CurBB->instructions().begin(), CurBB->instructions().end());

                          for (size_t i = 0; i < TempInsts.size()-1; ++i) 
                          {
                            OutlineBB->addInstruction(TempInsts[i]);
                          }

                          InstructionListType OutlineBBToNewBB = BC.MIB->createOutlinerToRedirectAnyOtherBB(16);
                          OutlineBB->addInstructions(OutlineBBToNewBB);

                          retBB->dump();

                          OutlineBB->setLabel(OutlineBBLabel);
                          OutlineBB->addSuccessor(retBB);
                          OutlineBB->setCFIState(retBB->getCFIState());
                          OutlineBB->setExecutionCount(0);

                          CurBB->clear();

                          InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                          CurBB->addInstructions(NewBBToOutliner);
                          CurBB->removeAllSuccessors();
                          CurBB->addSuccessor(OutlineBB);

                          // globalizeSymbolsAfterOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                          uint64_t CurBBSize = 0;

                          for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                              CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                          OutlineBB->setOffset(CurBB->getEndOffset());

                          uint64_t OutlineBBSize = 0;
                          for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                              OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          OutlineBB->setEndOffset(OutlineBB->getInputOffset() + OutlineBBSize);

                          // MasterBB->setOffset(OutlineBB->getEndOffset());

                          // MasterBBSize = 0;
                          // for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                          //     MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          // }
                          
                          // MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n*****\n";

                          // outs() << "retBB->dump()\n";

                          // MasterBB->dump();

                          // outs() << "\n*****\n";

                          first_block_to_be_outlined = false;
                      }
                  }

                  else 
                  {

                      if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
                      {
                          return Error::success();

                          outs() << "Outlined Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JUMPTHREAD_R11_RBP_Prologue: " << remainBigChunk << "\n";

                          CurBB->dump();

                          outs() << "\n******\n";

                          std::string OutlineBBName = "outline_"+blockHash;

                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                          auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                          if (!BC.MIB->checkCFIEqual(const_cast<BinaryBasicBlock *>(CurBB), const_cast<BinaryBasicBlock *>(OutlineBB)))
                            continue;

                          remainBigChunk += 1;

                          bool found = false;

                          OutlineBlockCounter += 1;

                          globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                          BinaryBasicBlock *PrologueBB = nullptr;
                          for (auto II = CurBB->begin(); II != CurBB->end(); ++II) 
                          {
                              MCInst &Inst = *II;

                              if (found)
                              {
                                  PrologueBB = CurBB->splitAt(II);
                                  break;
                              }

                              if (BC.MIB->SplitPrologue(Inst))
                              { 
                                found = true;
                              }
                          }
                    
                          BinaryBasicBlock::iterator SplitII;

                          if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(PrologueBB), &SplitII, SIZE_THRESHOLD, true))
                            continue;

                          BinaryBasicBlock *MasterBB = nullptr;

                          MasterBB = PrologueBB->splitAt(SplitII);

                          outs() << "SIZEMEETS JMPCONDUNCOND: \n";

                          PrologueBB->dump();

                          outs() << "\n******\n";

                          MasterBB->dump();

                          outs() << "\n******\n";

                          TotalBlocksOutlined += 1;

                          std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                          MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                          std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          std::replace(retBBName.begin(), retBBName.end(), '.', '_');
                          std::replace(retBBName.begin(), retBBName.end(), '/', '_');
                          std::replace(retBBName.begin(), retBBName.end(), '+', '_');

                          MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                          MCSymbol *OldLabel = CurBB->getLabel();

                          CurBB->setLabel(NewBBLabel);

                          for (BinaryBasicBlock *BB : Blocks) 
                          {
                              if (BB->succ_begin()!=BB->succ_end())
                              {
                                std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                for (BinaryBasicBlock *Succ : Successors) {

                                    if (Succ->getLabel() == OldLabel)
                                    {
                                      BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                    }
                                }
                              }
                          }
                          
                          MasterBB->setLabel(retBBLabel);

                          PrologueBB->clear();

                          OutlineBB->addSuccessor(MasterBB);

                          OutlineBB->setExecutionCount(OutlineBB->getExecutionCount()+1);

                          InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                          CurBB->addInstructions(NewBBToOutliner);
                          CurBB->removeAllSuccessors();
                          CurBB->addSuccessor(OutlineBB);

                          uint64_t CurBBSize = 0;

                          for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                              CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                          MasterBB->setOffset(CurBB->getEndOffset());

                          uint64_t MasterBBSize = 0;
                          for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                              MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n*****\n";

                          outs() << "retBB->dump()\n";

                          MasterBB->dump();

                          outs() << "\n*****\n";
                      }

                      else 
                      {
                          OutlineBlockCounter += 1;

                          globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                          outs() << "Outlined Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JUMPTHREAD_R11_RBP: " << remainBigChunk << "\n";

                          CurBB->dump();

                          outs() << "\n******\n";

                          remainBigChunk += 1;

                          
                    
                          BinaryBasicBlock::iterator SplitII;

                          if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(CurBB), &SplitII, SIZE_THRESHOLD, true))
                            continue;

                          TotalBlocksOutlined += 1;

                          outs() << "SIZEMEETS JMPCONDUNCOND: \n";

                          CurBB->dump();

                          outs() << "\n******\n";

                          std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                          std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                          MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                          auto retBB = CurBB->getSuccessor();

                          MCSymbol *retBBLabel = retBB->getLabel();

                          std::string OutlineBBName = "outline_"+blockHash;

                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                          std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                          auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                          MCSymbol *OldLabel = CurBB->getLabel();

                          CurBB->setLabel(NewBBLabel);

                          for (BinaryBasicBlock *BB : Blocks) 
                          {
                              if (BB->succ_begin()!=BB->succ_end())
                              {
                                std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                for (BinaryBasicBlock *Succ : Successors) {

                                    if (Succ->getLabel() == OldLabel)
                                    {
                                      BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                    }
                                }
                              }
                          }

                          OutlineBB->addSuccessor(retBB);
                          OutlineBB->setExecutionCount(OutlineBB->getExecutionCount()+1);

                          CurBB->clear();

                          InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                          CurBB->addInstructions(NewBBToOutliner);
                          CurBB->removeAllSuccessors();
                          CurBB->addSuccessor(OutlineBB);

                          uint64_t CurBBSize = 0;

                          for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                              CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n*****\n";
                      }
                  }

              }

          }

      }
  }



  else if (BC1.MIB->isEndingWithCondJump(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])) || BC1.MIB->isEndingWithUnCondJump(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])))
  {
    
    if (SIZE_THRESHOLD == 6)
    {
        no_rsp_rbp = true;

        count_thres_6_condJmps += 1;

        if (count_thres_6_condJmps == 343 || count_thres_6_condJmps == 611 || count_thres_6_condJmps == 616 || count_thres_6_condJmps == 684 || count_thres_6_condJmps == 2601 || count_thres_6_condJmps == 2704 || count_thres_6_condJmps == 2710 || count_thres_6_condJmps == 2920 || count_thres_6_condJmps == 2922 || count_thres_6_condJmps == 3482 || count_thres_6_condJmps == 3532 || count_thres_6_condJmps == 3538 || count_thres_6_condJmps == 4476 || count_thres_6_condJmps == 5093 || count_thres_6_condJmps == 5095 || count_thres_6_condJmps == 5478 || count_thres_6_condJmps == 6754)
        { 
          return Error::success();
        }

        // if (count_thres_6_condJmps > 6900)
        // { 
        //   return Error::success();
        // }

        outs() << "Thres_6_condJmps: " << count_thres_6_condJmps << "\n";

        static int OutlineBlockCounter = 0;

        static bool stackAdjusted = false;

        bool MasterStackAdjusted = false;

        BinaryFunction *OutlinedFunc;

        for (auto Function: Functions)
        {
            stackAdjusted = false; 

            BinaryContext &BC = Function->getBinaryContext();

            MCContext &Ctx = *BC.Ctx.get();

            auto it = std::find(OutlineStackAdjustedFuncs.begin(), OutlineStackAdjustedFuncs.end(), Function->getPrintName());

            if (it != OutlineStackAdjustedFuncs.end())
            {
              stackAdjusted = true;

              if (first_block_to_be_outlined)
                MasterStackAdjusted = true;
            }

            std::vector<BinaryBasicBlock *> Blocks(Function->pbegin(), Function->pend());

            for (BinaryBasicBlock *CurBB : Blocks) 
            {
                if (CurBB->empty())
                  continue;

                std::string block_hash = CurBB->getBlockHash();

                if (MasterStackAdjusted)
                  block_hash = BBHashMap[block_hash];

                if(block_hash.compare(blockHash) == 0)
                {
                    if (first_block_to_be_outlined)
                    {

                        outs() << "Master Function: " << Function->getPrintName() << " : JMPCONDUNCOND: " << remainBigChunk << "\n";

                        remainBigChunk += 1;

                        CurBB->dump();

                        outs() << "\n******\n";

                        BinaryBasicBlock *MasterBB = nullptr;
                  
                        BinaryBasicBlock::iterator SplitII;

                        if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(CurBB), &SplitII, SIZE_THRESHOLD+11, false))
                          return Error::success();

                        RedundantBlockCount += 1;

                        MasterBB = CurBB->splitAt(SplitII);

                        outs() << "SIZEMEETS NO_RSP_RBP: \n";

                        CurBB->dump();

                        outs() << "\n******\n";

                        MasterBB->dump();

                        outs() << "\n******\n";

                        OutlineBlockCounter += 1;

                        OutlinedFunc = Function;

                        std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                        MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                        std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                        MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);
                        
                        MasterBB->setLabel(retBBLabel);

                        std::string OutlineBBName = "outline_"+blockHash;

                        MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                        auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                        std::vector<MCInst> TempInsts(CurBB->instructions().begin(), CurBB->instructions().end());

                        for (size_t i = 0; i < TempInsts.size(); ++i) 
                        {
                          OutlineBB->addInstruction(TempInsts[i]);
                        }

                        MCInst RetInstr;
                        BC.MIB->createReturn(RetInstr);
                        OutlineBB->addInstruction(RetInstr);

                        OutlineBB->setLabel(OutlineBBLabel);

                        CurBB->clear();

                        MCInst MyCallInstr;
                        BC.MIB->createCall(MyCallInstr, OutlineBBLabel, &*BC.Ctx);
                        CurBB->addInstruction(MyCallInstr);

                        uint64_t CurBBSize = 0;

                        for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                            CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                        }

                        CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                        OutlineBB->setOffset(CurBB->getEndOffset());

                        uint64_t OutlineBBSize = 0;
                        for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                            OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                        }
                        
                        OutlineBB->setEndOffset(OutlineBB->getInputOffset() + OutlineBBSize);
                        OutlineBB->setCFIState(CurBB->getCFIState());
                        OutlineBB->setExecutionCount(CurBB->getExecutionCount());


                        MasterBB->setOffset(OutlineBB->getEndOffset());

                        uint64_t MasterBBSize = 0;
                        for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                            MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                        }
                        
                        MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                        outs() << "CurBB->dump()\n";

                        CurBB->dump();

                        outs() << "\n*****\n";

                        outs() << "OutlineBB->dump()\n";

                        OutlineBB->dump();

                        outs() << "\n*****\n";

                        outs() << "retBB->dump()\n";

                        MasterBB->dump();

                        outs() << "\n*****\n";

                        first_block_to_be_outlined = false;
                    }

                    else 
                    {

                        outs() << "Outlined Function: " << Function->getPrintName() << " : JMPCONDUNCOND: " << remainBigChunk << "\n";

                        remainBigChunk += 1;

                        CurBB->dump();

                        outs() << "\n******\n";

                        bool found = false;

                        BinaryBasicBlock *MasterBB = nullptr;
                  
                        BinaryBasicBlock::iterator SplitII;

                        if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(CurBB), &SplitII, SIZE_THRESHOLD+11, false))
                          continue;

                        OutlineBlockCounter += 1;

                        TotalBlocksOutlined += 1;

                        MasterBB = CurBB->splitAt(SplitII);

                        OutlineBlockCounter += 1;

                        std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                        MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                        std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                        MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);
                        
                        MasterBB->setLabel(retBBLabel);

                        std::string OutlineBBName = "outline_"+blockHash;

                        MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                        auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                        CurBB->clear();

                        MCInst MyCallInstr;
                        BC.MIB->createCall(MyCallInstr, OutlineBBLabel, &*BC.Ctx);
                        CurBB->addInstruction(MyCallInstr);

                        uint64_t CurBBSize = 0;

                        for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                            CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                        }

                        CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                        MasterBB->setOffset(CurBB->getEndOffset());

                        uint64_t MasterBBSize = 0;
                        for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                            MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                        }
                        
                        MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                        outs() << "CurBB->dump()\n";

                        CurBB->dump();

                        outs() << "\n*****\n";

                        outs() << "OutlineBB->dump()\n";

                        OutlineBB->dump();

                        outs() << "\n*****\n";

                        outs() << "retBB->dump()\n";

                        MasterBB->dump();

                        outs() << "\n*****\n";
                    }
                }
            }
        }
    }

    else if (SIZE_THRESHOLD == 25) 
    {
        return Error::success();

        if (BC1.MIB->hasCFI(const_cast<BinaryBasicBlock *>(BBSignatureMap[blockHash])))
        {
          return Error::success();
        }

        if (count_thres_25_condJmps == 5 || count_thres_25_condJmps == 6 || count_thres_25_condJmps == 7 || count_thres_25_condJmps == 30 || count_thres_25_condJmps == 40 || count_thres_25_condJmps == 41 || count_thres_25_condJmps == 42 || count_thres_25_condJmps == 45)
        { 
          count_thres_25_condJmps += 1;

          outs() << "Ignored JUMPCOND JMPR11RBP: " << count_thres_25_condJmps << "\n";

          BBSignatureMap[blockHash]->dump();

          outs() << "\n*****\n";

          return Error::success();
        }
        
        if (count_thres_25_condJmps > 50)
        { 
          return Error::success();
        }

        // return Error::success();

        // jmp_r11_rbp = true;

        // return Error::success();

        static int OutlineBlockCounter = 0;

        BinaryFunction *OutlinedFunc;

        for (auto Function: Functions)
        {
            BinaryContext &BC = Function->getBinaryContext();

            MCContext &Ctx = *BC.Ctx.get();

            auto it = std::find(OutlineStackAdjustedFuncs.begin(), OutlineStackAdjustedFuncs.end(), Function->getPrintName());

            if (it == OutlineStackAdjustedFuncs.end())
            {
              return Error::success();
            }

            std::vector<BinaryBasicBlock *> Blocks(Function->pbegin(), Function->pend());

            for (BinaryBasicBlock *CurBB : Blocks) 
            {
                if (CurBB->empty())
                  continue;

                std::string block_hash = CurBB->getBlockHash();

                block_hash = BBHashMap[block_hash];

                if(block_hash.compare(blockHash) == 0)
                {
                    if (first_block_to_be_outlined)
                    {

                        if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
                        {
                            

                            outs() << "Master Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JUMP_R11_RBP_Prologue: " << count_else_jmp_r11_rbp << ", SIZE_THRESHOLD: " << SIZE_THRESHOLD << "\n";

                            CurBB->dump();

                            outs() << "\n******\n";

                            bool found = false;

                            BinaryBasicBlock *PrologueBB = nullptr;
                            for (auto II = CurBB->begin(); II != CurBB->end(); ++II) 
                            {
                                MCInst &Inst = *II;

                                if (found)
                                {
                                    PrologueBB = CurBB->splitAt(II);
                                    break;
                                }

                                if (BC.MIB->SplitPrologue(Inst))
                                { 
                                  found = true;
                                }
                            }

                            found = false;

                            BinaryBasicBlock *MasterBB = nullptr;
                      
                            BinaryBasicBlock::iterator SplitII;

                            if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(PrologueBB), &SplitII, SIZE_THRESHOLD, false))
                              return Error::success();

                            count_thres_25_condJmps += 1;

                            outs() << "Thres_25_condJmps: " << count_thres_25_condJmps << "\n";

                            OutlineBlockCounter += 1;

                            globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                            RedundantBlockCount += 1;

                            MasterBB = PrologueBB->splitAt(SplitII);

                            outs() << "SIZEMEETS JMPCONDUNCOND: JMP_R11_RBP \n";

                            PrologueBB->dump();

                            outs() << "\n******\n";

                            MasterBB->dump();

                            outs() << "\n******\n";

                            OutlinedFunc = Function;

                            std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                            MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                            std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(retBBName.begin(), retBBName.end(), '.', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '/', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '+', '_');

                            MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                            MCSymbol *OldLabel = CurBB->getLabel();

                            CurBB->setLabel(NewBBLabel);

                            for (BinaryBasicBlock *BB : Blocks) 
                            {
                                if (BB->succ_begin()!=BB->succ_end())
                                {
                                  std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                  for (BinaryBasicBlock *Succ : Successors) {

                                      if (Succ->getLabel() == OldLabel)
                                      {
                                        BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                      }
                                  }
                                }
                            }
                            
                            MasterBB->setLabel(retBBLabel);

                            std::string OutlineBBName = "outline_"+blockHash;

                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                            MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                            auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                            std::vector<MCInst> TempInsts(PrologueBB->instructions().begin(), PrologueBB->instructions().end());

                            for (size_t i = 0; i < TempInsts.size(); ++i) 
                            {
                              OutlineBB->addInstruction(TempInsts[i]);
                            }

                            InstructionListType OutlineBBToNewBB = BC.MIB->createOutlinerToRedirectAnyOtherBB(16);
                            OutlineBB->addInstructions(OutlineBBToNewBB);

                            PrologueBB->clear();

                            OutlineBB->setLabel(OutlineBBLabel);
                            OutlineBB->addSuccessor(MasterBB);
                            OutlineBB->setCFIState(MasterBB->getCFIState());
                            OutlineBB->setExecutionCount(0);

                            InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                            CurBB->addInstructions(NewBBToOutliner);
                            CurBB->removeAllSuccessors();
                            CurBB->addSuccessor(OutlineBB);

                            uint64_t CurBBSize = 0;

                            for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                                CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }

                            CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                            OutlineBB->setOffset(CurBB->getEndOffset());

                            uint64_t OutlineBBSize = 0;
                            for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                                OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }
                            
                            OutlineBB->setEndOffset(OutlineBB->getInputOffset() + OutlineBBSize);

                            MasterBB->setOffset(OutlineBB->getEndOffset());

                            uint64_t MasterBBSize = 0;
                            for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                                MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }
                            
                            MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                            outs() << "CurBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";

                            outs() << "OutlineBB->dump()\n";

                            OutlineBB->dump();

                            outs() << "\n*****\n";

                            outs() << "retBB->dump()\n";

                            MasterBB->dump();

                            outs() << "\n*****\n";

                            first_block_to_be_outlined = false;
                        }

                        else 
                        {
                            

                            outs() << "Master Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JMP_R11_RBP: " << remainBigChunk << "\n";

                            remainBigChunk += 1;

                            CurBB->dump();

                            outs() << "\n******\n";

                            bool found = false;

                            BinaryBasicBlock *MasterBB = nullptr;
                      
                            BinaryBasicBlock::iterator SplitII;

                            if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(CurBB), &SplitII, SIZE_THRESHOLD, false))
                              return Error::success();

                            count_thres_25_condJmps += 1;

                            outs() << "Thres_25_condJmps: " << count_thres_25_condJmps << "\n";

                            OutlineBlockCounter += 1;

                            globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                            RedundantBlockCount += 1;

                            MasterBB = CurBB->splitAt(SplitII);

                            outs() << "SIZEMEETS JMPCONDUNCOND: JMP_R11_RBP \n";

                            CurBB->dump();

                            outs() << "\n******\n";

                            MasterBB->dump();

                            outs() << "\n******\n";

                            OutlinedFunc = Function;

                            std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                            MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                            std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(retBBName.begin(), retBBName.end(), '.', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '/', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '+', '_');

                            MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                            MCSymbol *OldLabel = CurBB->getLabel();

                            CurBB->setLabel(NewBBLabel);

                            for (BinaryBasicBlock *BB : Blocks) 
                            {
                                if (BB->succ_begin()!=BB->succ_end())
                                {
                                  std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                  for (BinaryBasicBlock *Succ : Successors) {

                                      if (Succ->getLabel() == OldLabel)
                                      {
                                        BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                      }
                                  }
                                }
                            }
                            
                            MasterBB->setLabel(retBBLabel);

                            std::string OutlineBBName = "outline_"+blockHash;

                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                            MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                            auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                            std::vector<MCInst> TempInsts(CurBB->instructions().begin(), CurBB->instructions().end());

                            for (size_t i = 0; i < TempInsts.size(); ++i) 
                            {
                              OutlineBB->addInstruction(TempInsts[i]);
                            }

                            InstructionListType OutlineBBToNewBB = BC.MIB->createOutlinerToRedirectAnyOtherBB(16);
                            OutlineBB->addInstructions(OutlineBBToNewBB);

                            OutlineBB->setLabel(OutlineBBLabel);
                            OutlineBB->addSuccessor(MasterBB);
                            OutlineBB->setCFIState(MasterBB->getCFIState());
                            OutlineBB->setExecutionCount(0);

                            CurBB->clear();

                            InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                            CurBB->addInstructions(NewBBToOutliner);
                            CurBB->removeAllSuccessors();
                            CurBB->addSuccessor(OutlineBB);

                            // globalizeSymbolsAfterOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                            uint64_t CurBBSize = 0;

                            for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                                CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }

                            CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                            OutlineBB->setOffset(CurBB->getEndOffset());

                            uint64_t OutlineBBSize = 0;
                            for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                                OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }
                            
                            OutlineBB->setEndOffset(OutlineBB->getInputOffset() + OutlineBBSize);

                            MasterBB->setOffset(OutlineBB->getEndOffset());

                            uint64_t MasterBBSize = 0;
                            for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                                MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }
                            
                            MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                            outs() << "CurBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";

                            outs() << "OutlineBB->dump()\n";

                            OutlineBB->dump();

                            outs() << "\n*****\n";

                            outs() << "retBB->dump()\n";

                            MasterBB->dump();

                            outs() << "\n*****\n";

                            first_block_to_be_outlined = false;
                        }
                    }

                    else 
                    {

                        if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
                        {
                            outs() << "Outlined Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JUMP_R11_RBP_Prologue: " << remainBigChunk << "\n";

                            CurBB->dump();

                            outs() << "\n******\n";

                            std::string OutlineBBName = "outline_"+blockHash;

                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                            MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                            auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                            if (!BC.MIB->checkCFIEqual(const_cast<BinaryBasicBlock *>(CurBB), const_cast<BinaryBasicBlock *>(OutlineBB)))
                              continue;

                            remainBigChunk += 1;

                            bool found = false;

                            OutlineBlockCounter += 1;

                            globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                            BinaryBasicBlock *PrologueBB = nullptr;
                            for (auto II = CurBB->begin(); II != CurBB->end(); ++II) 
                            {
                                MCInst &Inst = *II;

                                if (found)
                                {
                                    PrologueBB = CurBB->splitAt(II);
                                    break;
                                }

                                if (BC.MIB->SplitPrologue(Inst))
                                { 
                                  found = true;
                                }
                            }

                            found = false;

                            BinaryBasicBlock *MasterBB = nullptr;
                      
                            BinaryBasicBlock::iterator SplitII;

                            if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(PrologueBB), &SplitII, SIZE_THRESHOLD, false))
                              continue;

                            MasterBB = PrologueBB->splitAt(SplitII);
                            

                            outs() << "SIZEMEETS JMPCONDUNCOND: JMP_R11_RBP \n";

                            PrologueBB->dump();

                            outs() << "\n******\n";

                            MasterBB->dump();

                            outs() << "\n******\n";

                            TotalBlocksOutlined += 1;

                            std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                            MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                            std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(retBBName.begin(), retBBName.end(), '.', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '/', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '+', '_');

                            MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                            MCSymbol *OldLabel = CurBB->getLabel();

                            CurBB->setLabel(NewBBLabel);

                            for (BinaryBasicBlock *BB : Blocks) 
                            {
                                if (BB->succ_begin()!=BB->succ_end())
                                {
                                  std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                  for (BinaryBasicBlock *Succ : Successors) {

                                      if (Succ->getLabel() == OldLabel)
                                      {
                                        BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                      }
                                  }
                                }
                            }
                            
                            MasterBB->setLabel(retBBLabel);

                            PrologueBB->clear();

                            OutlineBB->addSuccessor(MasterBB);

                            OutlineBB->setExecutionCount(OutlineBB->getExecutionCount()+1);

                            InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                            CurBB->addInstructions(NewBBToOutliner);
                            CurBB->removeAllSuccessors();
                            CurBB->addSuccessor(OutlineBB);

                            uint64_t CurBBSize = 0;

                            for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                                CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }

                            CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                            MasterBB->setOffset(CurBB->getEndOffset());

                            uint64_t MasterBBSize = 0;
                            for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                                MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }
                            
                            MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                            outs() << "CurBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";

                            outs() << "OutlineBB->dump()\n";

                            OutlineBB->dump();

                            outs() << "\n*****\n";

                            outs() << "retBB->dump()\n";

                            MasterBB->dump();

                            outs() << "\n*****\n";
                        }

                        else 
                        {
                            OutlineBlockCounter += 1;

                            globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                            outs() << "Outlined Function: " << Function->getPrintName() << " : JMPCONDUNCOND: JMP_R11_RBP: " << remainBigChunk << "\n";

                            CurBB->dump();

                            outs() << "\n******\n";

                            remainBigChunk += 1;

                            TotalBlocksOutlined += 1;

                            bool found = false;

                            BinaryBasicBlock *MasterBB = nullptr;
                      
                            BinaryBasicBlock::iterator SplitII;

                            if (!isOutlineAbleAfterSplitting(BC, const_cast<BinaryBasicBlock *>(CurBB), &SplitII, SIZE_THRESHOLD, false))
                              continue;

                            MasterBB = CurBB->splitAt(SplitII);

                            outs() << "SIZEMEETS JMPCONDUNCOND: JMP_R11_RBP \n";

                            CurBB->dump();

                            outs() << "\n******\n";

                            MasterBB->dump();

                            outs() << "\n******\n";

                            std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(NewBBName.begin(), NewBBName.end(), '.', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '/', '_');
                            std::replace(NewBBName.begin(), NewBBName.end(), '+', '_');

                            MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                            std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                            std::replace(retBBName.begin(), retBBName.end(), '.', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '/', '_');
                            std::replace(retBBName.begin(), retBBName.end(), '+', '_');

                            MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                            std::string OutlineBBName = "outline_"+blockHash;

                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '.', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '/', '_');
                            std::replace(OutlineBBName.begin(), OutlineBBName.end(), '+', '_');

                            MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                            auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                            MCSymbol *OldLabel = CurBB->getLabel();

                            CurBB->setLabel(NewBBLabel);

                            for (BinaryBasicBlock *BB : Blocks) 
                            {
                                if (BB->succ_begin()!=BB->succ_end())
                                {
                                  std::vector<BinaryBasicBlock *> Successors = {BB->succ_begin(), BB->succ_end()};

                                  for (BinaryBasicBlock *Succ : Successors) {

                                      if (Succ->getLabel() == OldLabel)
                                      {
                                        BB->replaceSuccessor(Succ, CurBB, 0, 0);
                                      }
                                  }
                                }
                            }
                            
                            MasterBB->setLabel(retBBLabel);

                            OutlineBB->addSuccessor(MasterBB);
                            OutlineBB->setExecutionCount(OutlineBB->getExecutionCount()+1);

                            CurBB->clear();

                            InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);
                            CurBB->addInstructions(NewBBToOutliner);
                            CurBB->removeAllSuccessors();
                            CurBB->addSuccessor(OutlineBB);

                            // globalizeSymbolsAfterOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                            uint64_t CurBBSize = 0;

                            for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                                CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }

                            CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                            MasterBB->setOffset(CurBB->getEndOffset());

                            uint64_t MasterBBSize = 0;
                            for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                                MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                            }
                            
                            MasterBB->setEndOffset(MasterBB->getInputOffset() + MasterBBSize);

                            outs() << "CurBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";

                            outs() << "OutlineBB->dump()\n";

                            OutlineBB->dump();

                            outs() << "\n*****\n";

                            outs() << "retBB->dump()\n";

                            MasterBB->dump();

                            outs() << "\n*****\n";
                        }
                    }

                }

            }

        }
    }
  }

  else 
  {

    if (BBSignatureMap[blockHash]->pred_begin() == BBSignatureMap[blockHash]->pred_end() && BBSignatureMap[blockHash]->succ_begin() == BBSignatureMap[blockHash]->succ_end())
    {
        func_to_be_folded = true;
    }

    else 
    {
      if (SIZE_THRESHOLD == 6)
        no_rsp_rbp = true;
      else
        jmp_r11_rbp = true;
    }

    if (func_to_be_folded)
    {
        BinaryFunction *OutlinedFunc;

        static int OutlineBlockCounter = 0;

        bool stackAdjusted = false;

        for (auto Function: Functions) 
        {
            stackAdjusted = false;

            auto it = std::find(OutlineStackAdjustedFuncs.begin(), OutlineStackAdjustedFuncs.end(), Function->getPrintName());

            if (it != OutlineStackAdjustedFuncs.end())
            {
              stackAdjusted = true;
            }

            BinaryContext &BC = Function->getBinaryContext();

            MCContext &Ctx = *BC.Ctx.get();

            std::vector<BinaryBasicBlock *> Blocks(Function->pbegin(), Function->pend());

            for (BinaryBasicBlock *CurBB : Blocks) {

                if (CurBB->empty())
                  continue;

                std::string block_hash = CurBB->getBlockHash();

                if (stackAdjusted)
                  block_hash = BBHashMap[block_hash];

                if(block_hash.compare(blockHash) == 0)
                {
                    if (first_block_to_be_outlined)
                    {

                        RedundantBlockCount += 1;

                        OutlineBlockCounter += 1;

                        outs() << "Master Function: " << Function->getPrintName() << ", Address: " << Twine::utohexstr(Function->getAddress())  << ", Redundant BB: " << RedundantBlockCount << "\n";

                        outs() << "CurBB->dump()\n";
                        
                        CurBB->dump();

                        outs() << "\n*****\n";
                        
                        OutlinedFunc = Function;

                        first_block_to_be_outlined = false;

                    }

                    else 
                    {
                        std::string OutlineBBName = OutlinedFunc->getPrintName();

                        std::size_t Pos = OutlineBBName.find('(');
                        if (Pos != std::string::npos) {
                            
                            OutlineBBName = OutlineBBName.substr(0, Pos);
                        }

                        Pos = OutlineBBName.find('/');
                        if (Pos != std::string::npos) {
                            
                            OutlineBBName = OutlineBBName.substr(0, Pos);
                        }

                        MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                        std::vector<BinaryBasicBlock *> SuccBB = {CurBB->succ_begin(), CurBB->succ_end()};

                        if (CurBB->succ_begin() == CurBB->succ_end())
                        {
                            TotalBlocksOutlined += 1;

                            OutlineBlockCounter += 1;

                            outs() << "Outlined Function: " << Function->getPrintName() << " with " << Twine::utohexstr(OutlinedFunc->getAddress()) << "\n";

                            outs() << "CurBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";

                            CurBB->clear();

                            MCInst MyCallInstr;

                            uint64_t TargetAddr = OutlinedFunc->getAddress();
                            BC.MIB->createCallToAddress(MyCallInstr, TargetAddr, &*BC.Ctx);
                            CurBB->addInstruction(MyCallInstr);

                            MCInst RetInstr;
                            BC.MIB->createReturn(RetInstr);
                            CurBB->addInstruction(RetInstr);

                            outs() << "OutlineBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";
                        }

                        else if (SuccBB.size() > 0)
                        {

                            TotalBlocksOutlined += 1;

                            OutlineBlockCounter += 1;

                            outs() << "Outlined Function: " << Function->getPrintName() << "\n";

                            outs() << "CurBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";

                            CurBB->clear();

                            MCInst MyCallInstr;

                            uint64_t TargetAddr = OutlinedFunc->getAddress();
                            BC.MIB->createCallToAddress(MyCallInstr, TargetAddr, &*BC.Ctx);
                            CurBB->addInstruction(MyCallInstr);

                            outs() << "OutlineBB->dump()\n";

                            CurBB->dump();

                            outs() << "\n*****\n";
                        }
                    }
                }
            }
        }
    }

    else if (no_rsp_rbp)
    {
      BinaryFunction *OutlinedFunc;

      static int OutlineBlockCounter = 0;

      bool stackAdjusted = false;

      for (auto Function: Functions) 
      {
          stackAdjusted = false;

          auto it = std::find(OutlineStackAdjustedFuncs.begin(), OutlineStackAdjustedFuncs.end(), Function->getPrintName());

          if (it != OutlineStackAdjustedFuncs.end())
          {
            stackAdjusted = true;
          }

          BinaryContext &BC = Function->getBinaryContext();

          MCContext &Ctx = *BC.Ctx.get();

          std::vector<BinaryBasicBlock *> Blocks(Function->pbegin(), Function->pend());

          for (BinaryBasicBlock *CurBB : Blocks) {

              if (CurBB->empty())
                continue;

              std::string block_hash = CurBB->getBlockHash();

              if (stackAdjusted)
                block_hash = BBHashMap[block_hash];

              if(block_hash.compare(blockHash) == 0)
              {
                  if (first_block_to_be_outlined)
                  {

                      RedundantBlockCount += 1;

                      OutlineBlockCounter += 1;

                      outs() << "Master Function: NO_RSP_RBP: " << Function->getPrintName() << ", Address: " << Twine::utohexstr(Function->getAddress())  << ", Redundant BB: " << doing_trying_once << "\n";

                      outs() << "CurBB->dump()\n";
                      
                      CurBB->dump();

                      outs() << "\n*****\n";

                      std::vector<BinaryBasicBlock *> SuccBB = {CurBB->succ_begin(), CurBB->succ_end()};

                      if (SuccBB.size() > 0)
                      {
                          bool hasIndCallToRax = false;
                          if (BC.MIB->hasIndirectCalltoRAX(const_cast<BinaryBasicBlock *>(CurBB)))
                          {
                              hasIndCallToRax = true;
                          }

                          std::string OutlineBBName = "outline_"+blockHash;

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                          auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                          std::vector<MCInst> TempInsts(CurBB->instructions().begin(), CurBB->instructions().end());

                          for (size_t i = 0; i < TempInsts.size(); ++i) 
                          {
                            OutlineBB->addInstruction(TempInsts[i]);
                          }

                          MCInst RetInstr;
                          BC.MIB->createReturn(RetInstr);
                          OutlineBB->addInstruction(RetInstr);

                          // CurBB->setLabel(NewBBLabel);

                          CurBB->clear();

                          // if (hasIndCallToRax)
                          if (doing_trying_once == 1890 || doing_trying_once == 1886 || doing_trying_once == 1615 || doing_trying_once == 1612 || doing_trying_once == 1611 || doing_trying_once == 1444 || doing_trying_once == 1443 || doing_trying_once == 946 || doing_trying_once == 4)
                          {
                              outs() << "Adding RAX: " << doing_trying_once << "\n"; 
                              MCInst PushRaxInstr;
                              BC.MIB->pushRAX(PushRaxInstr, &*BC.Ctx);
                              CurBB->addInstruction(PushRaxInstr);
                          }

                          // if (doing_trying_once == 1444 || doing_trying_once == 1443 || doing_trying_once == 946 || doing_trying_once == 4)                        

                          MCInst MyCallInstr;
                          BC.MIB->createCall(MyCallInstr, OutlineBBLabel, &*BC.Ctx);
                          CurBB->addInstruction(MyCallInstr);

                         
                          // if (hasIndCallToRax)
                          if (doing_trying_once == 1890 || doing_trying_once == 1886 || doing_trying_once == 1615 || doing_trying_once == 1612 || doing_trying_once == 1611 || doing_trying_once == 1444 || doing_trying_once == 1443 || doing_trying_once == 946 || doing_trying_once == 4)
                          {
                            MCInst PopRaxInstr;
                            BC.MIB->popRAX(PopRaxInstr, &*BC.Ctx);
                            CurBB->addInstruction(PopRaxInstr);
                          }

                          uint64_t OutlineBBSize = 0;
                          for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                              OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          OutlineBB->setOffset(CurBB->getInputOffset() + OutlineBBSize);

                          // OutlineBB->setOffset(CurBB->getInputOffset());
                          OutlineBB->setCFIState(CurBB->getCFIState());

                          OutlineBB->setExecutionCount(CurBB->getExecutionCount());

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n*****\n";
                      
                          OutlinedFunc = Function;

                          doing_trying_once+=1;

                          first_block_to_be_outlined = false;

                      }

                      else 
                      {
                        
                          std::string OutlineBBName = "outline_"+blockHash;

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                          auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                          std::vector<MCInst> TempInsts(CurBB->instructions().begin(), CurBB->instructions().end());

                          for (size_t i = 0; i < TempInsts.size(); ++i) 
                          {
                            OutlineBB->addInstruction(TempInsts[i]);
                          }

                          CurBB->clear();

                          MCInst MyCallInstr;
                          BC.MIB->createCall(MyCallInstr, OutlineBBLabel, &*BC.Ctx);
                          CurBB->addInstruction(MyCallInstr);


                          uint64_t OutlineBBSize = 0;
                          for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                              OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          OutlineBB->setOffset(CurBB->getInputOffset() + OutlineBBSize);

                          OutlineBB->setCFIState(CurBB->getCFIState());

                          OutlineBB->setExecutionCount(CurBB->getExecutionCount());

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n*****\n";
                      
                          OutlinedFunc = Function;

                          first_block_to_be_outlined = false;
                      }
                  }

                  else 
                  {

                      bool hasIndCallToRax = false;
                      if (BC.MIB->hasIndirectCalltoRAX(const_cast<BinaryBasicBlock *>(CurBB)))
                      {
                          hasIndCallToRax = true;
                      }

                      std::string OutlineBBName = "outline_"+blockHash;

                      MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                      std::vector<BinaryBasicBlock *> SuccBB = {CurBB->succ_begin(), CurBB->succ_end()};

                      if (CurBB->succ_begin() == CurBB->succ_end())
                      {
                          TotalBlocksOutlined += 1;

                          OutlineBlockCounter += 1;

                          outs() << "Outlined Function: " << Function->getPrintName() << " with " << Twine::utohexstr(OutlinedFunc->getAddress()) << "\n";

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          CurBB->clear();

                          MCInst MyCallInstr;
                          BC.MIB->createCall(MyCallInstr, OutlineBBLabel, &*BC.Ctx);
                          CurBB->addInstruction(MyCallInstr);

                          MCInst RetInstr;
                          BC.MIB->createReturn(RetInstr);
                          CurBB->addInstruction(RetInstr);

                          outs() << "OutlineBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";
                      }

                      else if (SuccBB.size() > 0)
                      {

                          TotalBlocksOutlined += 1;

                          OutlineBlockCounter += 1;

                          outs() << "Outlined Function: " << Function->getPrintName() << "\n";

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";

                          CurBB->clear();

                          
                          // if (hasIndCallToRax)
                          if (doing_trying_once == 1891 || doing_trying_once == 1887 || doing_trying_once == 1616 || doing_trying_once == 1613 || doing_trying_once == 1612 || doing_trying_once == 1445 || doing_trying_once == 1444 || doing_trying_once == 947 || doing_trying_once == 5)
                          {
                              MCInst PushRaxInstr;
                              BC.MIB->pushRAX(PushRaxInstr, &*BC.Ctx);
                              CurBB->addInstruction(PushRaxInstr);
                          }

                          MCInst MyCallInstr;
                          BC.MIB->createCall(MyCallInstr, OutlineBBLabel, &*BC.Ctx);
                          CurBB->addInstruction(MyCallInstr);

                          
                          // if (hasIndCallToRax)
                          if (doing_trying_once == 1891 || doing_trying_once == 1887 || doing_trying_once == 1616 || doing_trying_once == 1613 || doing_trying_once == 1612 || doing_trying_once == 1445 || doing_trying_once == 1444 || doing_trying_once == 947 || doing_trying_once == 5)
                          {
                              MCInst PopRaxInstr;
                              BC.MIB->popRAX(PopRaxInstr, &*BC.Ctx);
                              CurBB->addInstruction(PopRaxInstr);
                          }

                          outs() << "OutlineBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n*****\n";
                      }
                  }
              }
          }
      }
    }

    else if (jmp_r11_rbp)
    {

      BinaryFunction *OutlinedFunc;

      static int OutlineBlockCounter = 0;

      for (auto Function: Functions) 
      {
          auto it = std::find(OutlineStackAdjustedFuncs.begin(), OutlineStackAdjustedFuncs.end(), Function->getPrintName());

          if (it == OutlineStackAdjustedFuncs.end())
          {
            return Error::success();
          }

          BinaryContext &BC = Function->getBinaryContext();

          MCContext &Ctx = *BC.Ctx.get();

          std::vector<BinaryBasicBlock *> Blocks(Function->pbegin(), Function->pend());

          for (BinaryBasicBlock *CurBB : Blocks) {

              if (CurBB->empty())
                continue;

              std::string block_hash = CurBB->getBlockHash();

              block_hash = BBHashMap[block_hash];

              if(block_hash.compare(blockHash) == 0)
              {
                  if (first_block_to_be_outlined)
                  {
                      if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
                      {
                          RedundantBlockCount += 1;

                          OutlineBlockCounter += 1;

                          OutlinedFunc = Function;

                          count_else_jmp_r11_rbp+=1;

                          outs() << "Master Function: " << Function->getPrintName() << " : JUMP_R11_RBP_Prologue: " << count_else_jmp_r11_rbp << ", SIZE_THRESHOLD: " << SIZE_THRESHOLD << "\n";

                          CurBB->dump();

                          outs() << "\n******\n";

                          bool found = false;

                          BinaryBasicBlock *MasterBB = nullptr;

                          for (auto II = CurBB->begin(); II != CurBB->end(); ++II) {
                              MCInst &Inst = *II;

                              if (found)
                              {
                                  MasterBB = CurBB->splitAt(II);
                                  break;
                              }

                              if (BC.MIB->SplitPrologue(Inst))
                              { 
                                found = true;
                              }
                          }

                          uint64_t MasterBBSize = 0;

                          for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                              MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          if (MasterBBSize < SIZE_THRESHOLD)
                            return Error::success();

                          MasterBB->dump();

                          outs() << "\n******\n";

                          count_else_jmp_r11_rbp+=1;

                          std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                          std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                          auto retBB = Function->addBasicBlock(retBBLabel);

                          std::string OutlineBBName = "outline_"+blockHash;

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                          auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                          OutlineBB->setLabel(OutlineBBLabel);

                          retBB->setLabel(retBBLabel);

                          InstructionListType OutlineBBToNewBB = BC.MIB->createOutlinerToRedirectAnyOtherBB(16);

                          std::vector<MCInst> TempInsts(MasterBB->instructions().begin(), MasterBB->instructions().end());

                          for (size_t i = 0; i < TempInsts.size(); ++i) 
                          {
                            OutlineBB->addInstruction(TempInsts[i]);
                          }

                          OutlineBB->addInstructions(OutlineBBToNewBB);

                          MasterBB->moveAllSuccessorsTo(retBB);
                          retBB->setCFIState(MasterBB->getCFIState());
                          retBB->setExecutionCount(MasterBB->getExecutionCount());

                          MasterBB->clear();

                          CurBB->removeAllSuccessors();

                          CurBB->addSuccessor(OutlineBB);

                          OutlineBB->addSuccessor(retBB);
                          OutlineBB->setCFIState(retBB->getCFIState());
                          OutlineBB->setExecutionCount(CurBB->getCFIState());

                          CurBB->setLabel(NewBBLabel);

                          InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);

                          CurBB->addInstructions(NewBBToOutliner);

                          uint64_t CurBBSize = 0;

                          for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                              CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                          OutlineBB->setOffset(CurBB->getEndOffset());

                          retBB->setOffset(OutlineBB->getEndOffset());

                          uint64_t retBBSize = 0;
                          for (auto Itr = retBB->begin(); Itr != retBB->end(); ++Itr) {
                              retBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          retBB->setEndOffset(retBB->getInputOffset() + retBBSize);

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n****\n";

                          outs() << "retBB->dump()\n";

                          retBB->dump();

                          outs() << "\n****\n";
                          
                          first_block_to_be_outlined = false;
                      }

                      else 
                      {
                          RedundantBlockCount += 1;

                          OutlineBlockCounter += 1;

                          outs() << "Master Function: " << Function->getPrintName() << " : Jump_R11_RBP: " << count_else_jmp_r11_rbp << "\n";

                          CurBB->dump();

                          outs() << "\n******\n";

                          std::vector<BinaryBasicBlock *> NextBB1 = {CurBB->succ_begin(), CurBB->succ_end()};

                          count_else_jmp_r11_rbp+=1;

                          OutlinedFunc = Function;

                          MCSymbol *OldLabel = CurBB->getLabel();

                          std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                          std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                          MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                          auto retBB = Function->addBasicBlock(retBBLabel);

                          std::string OutlineBBName = "outline_"+blockHash;

                          MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                          auto OutlineBB = Function->addBasicBlock(OutlineBBLabel);

                          OutlineBB->setOffset(CurBB->getInputOffset()); 

                          retBB->setLabel(retBBLabel);

                          InstructionListType OutlineBBToNewBB = BC.MIB->createOutlinerToRedirectAnyOtherBB(16);

                          std::vector<MCInst> TempInsts(CurBB->instructions().begin(), CurBB->instructions().end());

                          for (size_t i = 0; i < TempInsts.size(); ++i) 
                          {
                            OutlineBB->addInstruction(TempInsts[i]);
                          }

                          CurBB->moveAllSuccessorsTo(retBB);

                          retBB->setCFIState(CurBB->getCFIState());
                          retBB->setExecutionCount(CurBB->getExecutionCount());

                          OutlineBB->addInstructions(OutlineBBToNewBB);

                          OutlineBB->addSuccessor(retBB);

                          OutlineBB->setCFIState(retBB->getCFIState());

                          OutlineBB->setExecutionCount(0);

                          if (CurBB->getKnownExecutionCount() > 0)
                            OutlineBB->setExecutionCount(1);

                          CurBB->setLabel(NewBBLabel);

                          CurBB->clear();

                          InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);

                          CurBB->addInstructions(NewBBToOutliner);

                          CurBB->addSuccessor(OutlineBB);

                          OutlineBB->setOffset(CurBB->getEndOffset());

                          uint64_t CurBBSize = 0;

                          for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                              CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                          uint64_t OutlineBBSize = 0;

                          OutlineBB->setOffset(CurBB->getEndOffset());

                          for (auto Itr = OutlineBB->begin(); Itr != OutlineBB->end(); ++Itr) {
                              OutlineBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }

                          OutlineBB->setEndOffset(OutlineBB->getInputOffset() + OutlineBBSize);

                          retBB->setOffset(OutlineBB->getEndOffset());

                          uint64_t retBBSize = 0;
                          for (auto Itr = retBB->begin(); Itr != retBB->end(); ++Itr) {
                              retBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                          }
                          
                          retBB->setEndOffset(retBB->getInputOffset() + retBBSize);

                          first_block_to_be_outlined = false;

                          outs() << "CurBB->dump()\n";

                          CurBB->dump();

                          outs() << "\n****\n";

                          outs() << "OutlineBB->dump()\n";

                          OutlineBB->dump();

                          outs() << "\n****\n";

                          outs() << "retBB->dump()\n";

                          retBB->dump();

                          outs() << "\n****\n";

                          

                          first_block_to_be_outlined = false;
                      }
                  }

                  else 
                  {

                    if (BC.MIB->isPrologue(const_cast<BinaryBasicBlock *>(CurBB)))
                    {
                      count_else_jmp_r11_rbp+=1;

                      OutlineBlockCounter += 1;

                      globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                      outs() << "Outlined Function: " << Function->getPrintName() << "\n";

                      CurBB->dump();

                      outs() << "\n****\n";

                      bool found = false;

                      BinaryBasicBlock *MasterBB = nullptr;
                      for (auto II = CurBB->begin(); II != CurBB->end(); ++II) {
                          MCInst &Inst = *II;

                          if (found)
                          {
                              MasterBB = CurBB->splitAt(II);
                              break;
                          }

                          if (BC.MIB->SplitPrologue(Inst))
                          { 
                            found = true;
                          }
                      }

                      uint64_t MasterBBSize = 0;

                      for (auto Itr = MasterBB->begin(); Itr != MasterBB->end(); ++Itr) {
                          MasterBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                      }

                      if (MasterBBSize < SIZE_THRESHOLD)
                        continue;

                      TotalBlocksOutlined += 1;

                      std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                      MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                      std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                      MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                      auto retBB = Function->addBasicBlock(retBBLabel);

                      std::string OutlineBBName = "outline_"+blockHash;

                      MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                      auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                      retBB->setLabel(retBBLabel);

                      CurBB->setLabel(NewBBLabel);

                      OutlineBB->addSuccessor(retBB);

                      OutlineBB->setExecutionCount(OutlineBB->getExecutionCount()+1);

                      MasterBB->moveAllSuccessorsTo(retBB);
                      retBB->setCFIState(MasterBB->getCFIState());
                      retBB->setExecutionCount(MasterBB->getExecutionCount());

                      MasterBB->clear();

                      CurBB->removeAllSuccessors();

                      CurBB->addSuccessor(OutlineBB);

                      InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);

                      CurBB->addInstructions(NewBBToOutliner);

                      uint64_t CurBBSize = 0;

                      for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                          CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                      }

                      CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                      retBB->setOffset(CurBB->getEndOffset());

                      uint64_t retBBSize = 0;
                      for (auto Itr = retBB->begin(); Itr != retBB->end(); ++Itr) {
                          retBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                      }
                      
                      retBB->setEndOffset(retBB->getInputOffset() + retBBSize);

                      outs() << "CurBB->dump()\n";

                      CurBB->dump();

                      outs() << "\n****\n";

                      outs() << "OutlineBB->dump()\n";

                      OutlineBB->dump();

                      outs() << "\n****\n";

                      outs() << "retBB->dump()\n";

                      retBB->dump();

                      outs() << "\n****\n";

                      
                    }

                    else 
                    {
                      std::vector<BinaryBasicBlock *> NextBB1 = {CurBB->succ_begin(), CurBB->succ_end()};

                      OutlineBlockCounter += 1;

                      globalizeSymbolsBeforeOutline(BC, Function, Blocks, OutlineBlockCounter, blockHash);

                      outs() << "Outlined Function: " << Function->getPrintName() << " : Jump_R11_RBP: " << count_else_jmp_r11_rbp << "\n";

                      CurBB->dump();

                      outs() << "\n******\n";

                      MCSymbol *OldLabel = CurBB->getLabel();

                      std::string NewBBName = "BB_before_outline_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                      MCSymbol *NewBBLabel = BC.getOrCreateUndefinedGlobalSymbol(NewBBName);

                      std::string retBBName = "ret_"+blockHash+"_"+std::to_string(OutlineBlockCounter);

                      MCSymbol *retBBLabel = BC.getOrCreateUndefinedGlobalSymbol(retBBName);

                      auto retBB = Function->addBasicBlock(retBBLabel);

                      std::string OutlineBBName = "outline_"+blockHash;

                      MCSymbol *OutlineBBLabel = BC.getOrCreateUndefinedGlobalSymbol(OutlineBBName);

                      auto OutlineBB = OutlinedFunc->getBasicBlockForLabel(OutlineBBLabel);

                      retBB->setLabel(retBBLabel);

                      CurBB->moveAllSuccessorsTo(retBB);

                      retBB->setCFIState(CurBB->getCFIState());
                      retBB->setExecutionCount(CurBB->getExecutionCount());

                      OutlineBB->addSuccessor(retBB);

                      OutlineBB->setExecutionCount(OutlineBB->getExecutionCount()+1);

                      CurBB->setLabel(NewBBLabel);

                      CurBB->clear();

                      InstructionListType NewBBToOutliner = BC.MIB->createRedirectToOutlinerAnyOtherBB(retBBLabel, OutlineBBLabel, 16, &Ctx);

                      CurBB->addInstructions(NewBBToOutliner);

                      CurBB->addSuccessor(OutlineBB);

                      uint64_t CurBBSize = 0;

                      for (auto Itr = CurBB->begin(); Itr != CurBB->end(); ++Itr) {
                          CurBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                      }

                      CurBB->setEndOffset(CurBB->getInputOffset() + CurBBSize);

                      retBB->setOffset(CurBB->getEndOffset());

                      uint64_t retBBSize = 0;
                      for (auto Itr = retBB->begin(); Itr != retBB->end(); ++Itr) {
                          retBBSize += BC.computeCodeSize(Itr, std::next(Itr));
                      }
                      
                      retBB->setEndOffset(retBB->getInputOffset() + retBBSize);

                      outs() << "CurBB->dump()\n";

                      CurBB->dump();

                      outs() << "\n****\n";

                      outs() << "OutlineBB->dump()\n";

                      OutlineBB->dump();

                      outs() << "\n****\n";

                      outs() << "retBB->dump()\n";

                      retBB->dump();

                      outs() << "\n****\n";
                    }
                  }
              }
          }
      }
    }        
  }

  return Error::success();
}

Error OutlineSimBB::runOnFunctions(BinaryContext &BC) {
  if (!BC.isX86())
    return Error::success();

  outs() << "BOLT-INFO: Running BB Outlining Pass\n";

  MCContext &Ctx = *BC.Ctx.get();

  static int RedundantBlockCount = 0;

  static int RedundantBlockCount1 = 0;

  static int TotalBlocksOutlined = 0;

  static int countRemaining = 0;

  for (const auto &Entry : BBCommonMap) 
  {

    const auto *MetaData = Entry.second;

    if ((MetaData->count <= 1 || MetaData->original_size < MetaData->Threshold))
      continue;

    if (MetaData->RetOrIndJump)
    {
        // if (RedundantBlockCount == 152)
        // {
        //   outs() << "ToIgnore: " << RedundantBlockCount << "\n";
        //   outs() << "BOLT-INFO: Outlining RetOrIndJmpBB - " << RedundantBlockCount + 1 << " with block hash: " << MetaData->block_hash << "\n";
        //   RedundantBlockCount += 1;
        //   continue;
        // }
        std::string toIgnore = "488b50000c3";
        if (toIgnore.compare(MetaData->block_hash) == 0)
          continue;

        outs() << "BOLT-INFO: Outlining RetOrIndJmpBB - " << RedundantBlockCount + 1 << " with block hash: " << MetaData->block_hash << "\n";
    

        BBSignatureMap[MetaData->block_hash]->dump();
        outs() << "*****************\n";

        outlineRetIndJmp(MetaData->function_vec, MetaData->block_hash, RedundantBlockCount, TotalBlocksOutlined);
    }

    else 
    {
        std::string toIgnore = "498b7c248488b7ff50484883c42031c05b415c415d415e5dc3";
        std::string toIgnore1 = "488b5424404531c94531c031c9bec60004889dfe80000_ZN11xercesc_2_710XMLScanner9emitErrorENS_7XMLErrs5CodesEPKtS4_S4_S4_";
        std::string toIgnore2 = "498b64c89fe4c89e749ffc74c8b6810488b34c8b90e0200498b4244c8955c0ff50184c8b55c031c9ba10004889c64889df41ffd24c89f74889c641ffd5";
        std::string toIgnore3 = "4889dfbe2d000e80000_ZN11xalanc_1_1016XalanUTF16Writer5writeEt4889dfbe2d000e80000_ZN11xalanc_1_1016XalanUTF16Writer5writeEt4883c4184889dfbe3e0005b415c415d415e415f5de90000_ZN11xalanc_1_1016XalanUTF16Writer5writeEt";
        if (toIgnore.compare(MetaData->block_hash) == 0 || toIgnore1.compare(MetaData->block_hash)==0 || toIgnore2.compare(MetaData->block_hash)==0 || toIgnore3.compare(MetaData->block_hash)==0)
          continue;

        outs() << "BOLT-INFO: Outlining AnyOtherBB - " << RedundantBlockCount1 << " with block hash: " << MetaData->block_hash << "\n";
    
        BBSignatureMap[MetaData->block_hash]->dump();
        outs() << "*****************\n";

        outlineAnyOtherBB(MetaData->function_vec, MetaData->block_hash, RedundantBlockCount1, TotalBlocksOutlined, MetaData->Threshold, countRemaining);
    }

  }

  outs() << "BOLT-INFO: Outlined Redundant Blocks = " << RedundantBlockCount + RedundantBlockCount1 << "\n";
  outs() << "BOLT-INFO: Removed Redundant Basic Blocks = " << TotalBlocksOutlined << "\n";

  outs() << "BOLT-INFO: Count Remaining = " << count_thres_25_condJmps << "\n";
  
  return Error::success();

}

void RemoveNops::runOnFunction(BinaryFunction &BF) {
  const BinaryContext &BC = BF.getBinaryContext();
  for (BinaryBasicBlock &BB : BF) {
    for (int64_t I = BB.size() - 1; I >= 0; --I) {
      MCInst &Inst = BB.getInstructionAtIndex(I);
      if (BC.MIB->isNoop(Inst) && BC.MIB->hasAnnotation(Inst, "NOP"))
        BB.eraseInstructionAtIndex(I);
    }
  }
}

Error RemoveNops::runOnFunctions(BinaryContext &BC) {
  ParallelUtilities::WorkFuncTy WorkFun = [&](BinaryFunction &BF) {
    runOnFunction(BF);
  };

  ParallelUtilities::PredicateTy SkipFunc = [&](const BinaryFunction &BF) {
    return BF.shouldPreserveNops();
  };

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_INST_LINEAR, WorkFun,
      SkipFunc, "RemoveNops");
  return Error::success();
}

} // namespace bolt
} // namespace llvm
