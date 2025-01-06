//===-- llvm::IPRAPostRAAnalysis.cpp ---=========--------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// llvm::IPRAPostRAAnalysis implementation.
///
/// The purpose of this pass is to analyze register usage information post RA.
//===----------------------------------------------------------------------===//

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>

// #include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/BranchProbabilityInfo.h"
// #include "llvm/Analysis/EHUtils.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/BasicBlockSectionUtils.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineBlockFrequencyInfo.h"
#include "llvm/CodeGen/MBFIWrapper.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
// #include "llvm/MC/MCRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Pass.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Support/Debug.h"

// This file contains a list of function symbols that we would like to
// optimize, each symbol in a separate line
static llvm::cl::opt<std::string> IPRAFunctionSymsFile(
    "ipra-function-syms-file",
    llvm::cl::desc("File containing the symbol list, one symbol per line"),
    llvm::cl::init(""), llvm::cl::Hidden);

// To Only get Hot Entry Block Function names.
static llvm::cl::opt<bool> IPRAHotEntryBlocksOnly(
    "ipra-hot-entry-blocks-only",
    llvm::cl::desc("Dry run to get validclear function names"),
    llvm::cl::init(false), llvm::cl::Hidden);

// Look at hot Prologs and Epilogs that use equal or above this threshold
// Callee-saved registers.
static llvm::cl::opt<int>
    IPRARegUsageCount("ipra-regusage-count",
                      llvm::cl::desc("Reg Usage Count threshold"),
                      llvm::cl::init(6), llvm::cl::Hidden);

namespace llvm {
class IPRAPostRAAnalysis : public llvm::MachineFunctionPass {
 public:
  static char ID;
  llvm::StringMap<unsigned> FunctionSymsMap;

  IPRAPostRAAnalysis() : MachineFunctionPass(ID) {
    initializeIPRAPostRAAnalysisPass(*llvm::PassRegistry::getPassRegistry());
  }

  llvm::StringRef getPassName() const override {
    return "IPRA Prolog-Epilog Post Reg Alloc Analysis";
  }

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

  /// Analyze callee saved register usage of hot entry functions
  bool runOnMachineFunction(llvm::MachineFunction &MF) override;
};

char IPRAPostRAAnalysis::ID = 0;

}  // namespace llvm

static bool isHotBasicBlock(const llvm::MachineBasicBlock &MBB,
                            const llvm::MachineBlockFrequencyInfo *MBFI,
                            llvm::ProfileSummaryInfo *PSI,
                            uint64_t &CountVal) {
  std::optional<uint64_t> Count = MBFI->getBlockProfileCount(&MBB);
  bool debug = false;
  if (MBB.getParent()->getName() == "__try_to_wake_up" ||
      MBB.getParent()->getName() == "wake_up_new_task") {
    llvm::dbgs() << "IPRA (inside isHotBasicBlock): "
                 << (Count.has_value() ? Count.value() : 0) << "\n";
    debug = true;
  }
  CountVal = (Count.has_value() ? Count.value() : 0);
  if (!Count) {
    // if (debug) fprintf(stderr, "isHotBasicBlock return false");
    return false;
  }
  if (PSI->isHotCount(*Count)) {
    // if (debug) fprintf(stderr, "isHotBasicBlock return true");
    CountVal = *Count;
    return true;
  }
  // if (debug) fprintf(stderr, "isHotBasicBlock return false");
  return false;
}

// Returns true if this Machine Function uses up RegThreshold or more
// callee-saved registers.
static bool areAllCSRegsUsed(const llvm::MachineFunction &MF, int RegThreshold,
                             int &RegCount) {
  const llvm::MCPhysReg *CSRegs = MF.getRegInfo().getCalleeSavedRegs();
  if (!CSRegs || CSRegs[0] == 0)
    return false;
  bool CallsUnwindInit = MF.callsUnwindInit();
  const llvm::MachineRegisterInfo &MRI = MF.getRegInfo();
  int count = 0;
  for (unsigned i = 0; CSRegs[i]; ++i) {
    unsigned Reg = CSRegs[i];
    if (CallsUnwindInit || MRI.isPhysRegModified(Reg))
      count++;
  }
  RegCount = count;
  return count >= RegThreshold;
}

static int printCSRegsAliveAtPoint(const llvm::MachineFunction &MF,
                                    const llvm::LivePhysRegs &LiveRegs) {
  const llvm::MCPhysReg *CSRegs = MF.getRegInfo().getCalleeSavedRegs();
  if (!CSRegs || CSRegs[0] == 0 || LiveRegs.empty())
    return false;

  fprintf(stderr, "IPRA: Registers live out:");
  int count = 0;
  for (unsigned i = 0; CSRegs[i]; ++i) {
    unsigned Reg = CSRegs[i];
    if (LiveRegs.contains(Reg)) {
      fprintf(stderr, " Register %d", i);
    } else if (i > 0) {
      count++;
    }
  }
  fprintf(stderr, "\n");
  return count;
}

static unsigned int
parseSymbolsFile(llvm::StringMap<unsigned> &FunctionSymsMap) {
  auto BufferOrErr = llvm::MemoryBuffer::getFile(IPRAFunctionSymsFile, true);
  auto EC = BufferOrErr.getError();
  if (EC) {
    llvm::dbgs() << "Could not open remarks file: "  << EC.message();
    return 0;
  }
  llvm::line_iterator LineIt(*BufferOrErr.get(), /*SkipBlanks=*/true);
  unsigned int count = 0;
  for (; !LineIt.is_at_eof(); ++LineIt) {
    llvm::StringRef Line = *LineIt;
    FunctionSymsMap[Line.str()] = 0;
    count++;
  }
  // llvm::dbgs() << "IPRA: Returing count = " << count << " values\n";
  return count;
}

bool llvm::IPRAPostRAAnalysis::runOnMachineFunction(MachineFunction &MF) {
  if (!MF.getFunction().hasProfileData()) {
    // llvm::dbgs() << "IPRA: " << MF.getName() << " : No profile data
    // found...exiting\n";
    // fprintf(stderr, "IPRA: %s : No profile data found...exiting\n",
    //         MF.getName().str().c_str());
    return false;
  }

  unsigned int MapEleCount = 0;
  if (IPRAFunctionSymsFile != "")
    MapEleCount = parseSymbolsFile(FunctionSymsMap);

  MBFIWrapper *MBFI = nullptr;
  ProfileSummaryInfo *PSI = nullptr;

  MBFIWrapper MBBFreqInfo(
      getAnalysis<MachineBlockFrequencyInfoWrapperPass>().getMBFI());
  MBFI =&MBBFreqInfo;

  PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
  uint64_t CountVal = 0;
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  LivePhysRegs LiveRegs;
  LiveRegs.init(*TRI);
  int RegCount = 0;

  for (auto &MBB : MF) {
    // if (MBB.isEntryBlock() &&
    //     !isHotBasicBlock(MBB, &MBFI->getMBFI(), PSI, CountVal)) {
    //   fprintf(stderr, "%s is not hot\n", MF.getName().str().c_str());
    // }
    if (MBB.isEntryBlock() &&
        isHotBasicBlock(MBB, &MBFI->getMBFI(), PSI, CountVal)) {
        if (areAllCSRegsUsed(MF, IPRARegUsageCount, RegCount))
          fprintf(stderr, "IPRA: %lu %s (%d)\n", CountVal,
                  MF.getName().str().c_str(), RegCount);
          // llvm::dbgs() << "IPRA: " << CountVal << " " << MF.getName()
          //        << " (" << RegCount << ")" << "\n";
    }
    if (IPRAHotEntryBlocksOnly)
      continue;
    // Visit the basic block instructions in reverse
    // for liveness analysis to work.
    LiveRegs.init(*TRI);
    LiveRegs.addLiveOuts(MBB);
    for (const MachineInstr &MI : llvm::reverse(MBB)) {
      if (MI.isCall() && MI.getNumOperands() && MI.getOperand(0).isGlobal()) {
        // MI.print(llvm::dbgs());
        std::string glob_name =
            MI.getOperand(0).getGlobal()->getGlobalIdentifier();
        bool isHot = isHotBasicBlock(MBB, &MBFI->getMBFI(), PSI, CountVal);
        if ((MapEleCount == 0 || FunctionSymsMap.contains(glob_name)) &&
            isHot) {
          int count = printCSRegsAliveAtPoint(MF, LiveRegs);
          llvm::dbgs() << "IPRA: CallSite in: " << MF.getName() << " to "
                       << glob_name << " with hotness : " << CountVal << " ( "
                       << CountVal * count << " ) (isHotBasicBlock=" << isHot
                       << ")\n";
        }
      }
      LiveRegs.stepBackward(MI);
    }
  }

  return true;
}

void llvm::IPRAPostRAAnalysis::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<MachineModuleInfoWrapperPass>();
  AU.addRequired<MachineBlockFrequencyInfoWrapperPass>();
  AU.addRequired<ProfileSummaryInfoWrapperPass>();
  // AU.setPreservesAll();
  // MachineFunctionPass::getAnalysisUsage(AU);
}

llvm::MachineFunctionPass *llvm::createIPRAPostRAAnalysisPass() {
  return new llvm::IPRAPostRAAnalysis();
}

using namespace llvm;

INITIALIZE_PASS_BEGIN(
    IPRAPostRAAnalysis, "ipra-postra-analysis",
    "Analysis for IPRA Post Register Allocation", false,
    false)

INITIALIZE_PASS_END(
    IPRAPostRAAnalysis, "ipra-postra-analysis",
    "Analysis for IPRA Post Register Allocation", false,
    false)

