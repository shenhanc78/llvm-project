//===-- IPRAPostRAAnalysis.cpp ---=========-----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// IPRAPostRAAnalysis implementation.
///
/// The purpose of this pass is to analyze register usage information post RA.
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/BranchProbabilityInfo.h"
#include "llvm/Analysis/EHUtils.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/BasicBlockSectionUtils.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineBlockFrequencyInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/LineIterator.h"
#include <optional>

using namespace llvm;

// This file contains a list of function symbols that we would like to
// optimize, each symbol in a separate line
static cl::opt<std::string>
    IPRAFunctionSymsFile("ipra-function-syms-file",
                         cl::desc("File containing the symbol list, one symbol per line"),
                         cl::init(""), cl::Hidden);

// To Only get Hot Entry Block Function names.
static cl::opt<bool>
    IPRAHotEntryBlocksOnly("ipra-hot-entry-blocks-only", cl::desc("Dry run to get valid function names"),
               cl::init(false), cl::Hidden);


// Look at hot Prologs and Epilogs that use equal or above this threshold Callee-saved registers.
static cl::opt<int>
    IPRARegUsageCount("ipra-regusage-count", cl::desc("Reg Usage Count threshold"),
               cl::init(6), cl::Hidden);

namespace llvm {
class IPRAPostRAAnalysis : public MachineFunctionPass {
public:
  static char ID;
  StringMap<unsigned> FunctionSymsMap;

  IPRAPostRAAnalysis() : MachineFunctionPass(ID) {
    initializeIPRAPostRAAnalysisPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "IPRA Prolog-Epilog Post Reg Alloc Analysis"; }

  void getAnalysisUsage(AnalysisUsage &AU) const override;

  /// Analyze callee saved register usage of hot entry functions
  bool runOnMachineFunction(MachineFunction &MF) override;
};

} // namespace llvm

char IPRAPostRAAnalysis::ID = 0;
INITIALIZE_PASS_BEGIN(
    IPRAPostRAAnalysis, "ipra-postra-analysis",
    "Analysis for IPRA Post Register Allocation", false,
    false)
INITIALIZE_PASS_END(
    IPRAPostRAAnalysis, "ipra-postra-analysis",
    "Analysis for IPRA Post Register Allocation", false,
    false)

static bool isHotBasicBlock(const MachineBasicBlock &MBB,
                            const MachineBlockFrequencyInfo *MBFI,
                            ProfileSummaryInfo *PSI,
                            uint64_t &CountVal) {
  std::optional<uint64_t> Count = MBFI->getBlockProfileCount(&MBB);
  if (!Count)
    return false;
  if (PSI->isHotCount(*Count)) {
    // dbgs() << "IPRA: " << *Count;
    CountVal = *Count;
    return true;
  }
  return false;
}

// Returns true if this Machine Function uses up RegThreshold or more
// callee-saved registers.
static bool areAllCSRegsUsed(const MachineFunction &MF, int RegThreshold,
                             int &RegCount) {
  const MCPhysReg *CSRegs = MF.getRegInfo().getCalleeSavedRegs();
  if (!CSRegs || CSRegs[0] == 0)
    return false;
  bool CallsUnwindInit = MF.callsUnwindInit();
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  int count = 0;
  for (unsigned i = 0; CSRegs[i]; ++i) {
    unsigned Reg = CSRegs[i];
    if (CallsUnwindInit || MRI.isPhysRegModified(Reg))
      count++;   
  }
  RegCount = count;
  return count >= RegThreshold;
}

static int printCSRegsAliveAtPoint(const MachineFunction &MF,
                                    const LivePhysRegs &LiveRegs) {
  const MCPhysReg *CSRegs = MF.getRegInfo().getCalleeSavedRegs();
  if (!CSRegs || CSRegs[0] == 0 || LiveRegs.empty())
    return false;

  dbgs() << "IPRA: Registers live out : ";
  int count = 0;
  for (unsigned i = 0; CSRegs[i]; ++i) {
    unsigned Reg = CSRegs[i];
    if (LiveRegs.contains(Reg)) {
        dbgs() << "Register " << i << " , ";
    } else if (i > 0) {
        count++;
    }
  }
  dbgs() << "\n";
  return count;                                    
}

static unsigned int parseSymbolsFile(StringMap<unsigned> &FunctionSymsMap) {
  auto BufferOrErr = MemoryBuffer::getFile(IPRAFunctionSymsFile, true);
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
  // dbgs() << "IPRA: Returing count = " << count << " values\n";
  return count;
}

bool IPRAPostRAAnalysis::runOnMachineFunction(MachineFunction &MF) {
  if (!MF.getFunction().hasProfileData()) {
    // dbgs() << "IPRA: " << MF.getName() << " : No profile data found...exiting\n";
    return false;
  }
 
  unsigned int MapEleCount = 0;
  
  if (IPRAFunctionSymsFile != "")
    MapEleCount = parseSymbolsFile(FunctionSymsMap);

  MachineBlockFrequencyInfo *MBFI = nullptr;
  ProfileSummaryInfo *PSI = nullptr;
  MBFI = &getAnalysis<MachineBlockFrequencyInfo>();
  PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
  uint64_t CountVal = 0;
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  LivePhysRegs LiveRegs;
  LiveRegs.init(*TRI);
  int RegCount = 0;

  for (auto &MBB : MF) {
    if (MBB.isEntryBlock() &&
        isHotBasicBlock(MBB, MBFI, PSI, CountVal)) {
        if (areAllCSRegsUsed(MF, IPRARegUsageCount, RegCount))
          dbgs() << "IPRA: " << CountVal << " " << MF.getName() 
                 << " (" << RegCount << ")" << "\n";
    }
    if (IPRAHotEntryBlocksOnly)
      continue;
    // Visit the basic block instructions in reverse
    // for liveness analysis to work.
    LiveRegs.init(*TRI);
    LiveRegs.addLiveOuts(MBB);
    for (const MachineInstr &MI : llvm::reverse(MBB)) {
      if (MI.isCall() && MI.getOperand(0).isGlobal()) {
        // MI.print(dbgs());
        std::string glob_name = MI.getOperand(0).getGlobal()->getGlobalIdentifier();
        if ((MapEleCount == 0 || FunctionSymsMap.contains(glob_name)) &&
            isHotBasicBlock(MBB, MBFI, PSI, CountVal)) {
          int count = printCSRegsAliveAtPoint(MF, LiveRegs);      
          dbgs() << "IPRA: CallSite in: " << MF.getName() << " to " << glob_name <<
                 " with hotness : " << CountVal << " ( " << CountVal*count << " )\n";
          
        }
      }
      LiveRegs.stepBackward(MI);
    }
  }
  
  return true;
}

void IPRAPostRAAnalysis::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<MachineModuleInfoWrapperPass>();
  AU.addRequired<MachineBlockFrequencyInfo>();
  AU.addRequired<ProfileSummaryInfoWrapperPass>();
  //AU.setPreservesAll();
  //MachineFunctionPass::getAnalysisUsage(AU);
}

MachineFunctionPass *llvm::createIPRAPostRAAnalysisPass() {
  return new IPRAPostRAAnalysis();
}
