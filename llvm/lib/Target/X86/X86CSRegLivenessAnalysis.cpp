#include <cstdint>
#include <iostream>
#include <optional>
#include <vector>

#include "llvm/ADT/iterator_range.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineBlockFrequencyInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/MBFIWrapper.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalObject.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/SymbolTableListTraits.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Target/TargetMachine.h"

#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86.h"
#include "X86Subtarget.h"

// For X86-64, include the X86.h header to get the register enums.
#include "llvm/Target/TargetOptions.h"
#include "llvm/MC/MCTargetOptions.h"

#define DEBUG_TYPE "cs-reg-liveness"

// This file contains a list of function symbols that we would like to
// optimize, each symbol in a separate line
static llvm::cl::opt<bool> EnableCSRegLivenessAnalysis(
    "enable-cs-reg-liveness-analysis",
    llvm::cl::desc("Enable callee-saved register liveness analysis"),
    llvm::cl::init(false), llvm::cl::Hidden);

namespace {

using namespace ::llvm;

bool isHotBasicBlock(const llvm::MachineBasicBlock &MBB,
                     const llvm::MachineBlockFrequencyInfo *MBFI,
                     const llvm::ProfileSummaryInfo *PSI,
                     uint64_t &CountVal) {
  std::optional<uint64_t> Count = MBFI->getBlockProfileCount(&MBB);
  CountVal = (Count.has_value() ? Count.value() : 0);
  return Count.has_value() && PSI->isHotCount(*Count);
}

class X86CSRegLivenessAnalysis : public MachineFunctionPass {
 public:
  static char ID;
  X86CSRegLivenessAnalysis() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

 private:
  const TargetRegisterInfo *TRI;
  const MachineRegisterInfo *MRI;
  const ProfileSummaryInfo *PSI;
  const MachineBlockFrequencyInfo *MBFI;

  // Set of callee-saved registers on x86-64
  std::vector<MCPhysReg> CalleeSavedRegs;

  bool calculateMachineFunctionCSRegUsage(const MachineFunction &MF);
  void calculateCalleeSavedLiveness(MachineFunction &MF);
  bool analyzeBasicBlock(MachineBasicBlock &MBB);
};

void X86CSRegLivenessAnalysis::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<MachineModuleInfoWrapperPass>();
  AU.addRequired<MachineBlockFrequencyInfoWrapperPass>();
  AU.addRequired<ProfileSummaryInfoWrapperPass>();
  // AU.setPreservesAll();
  // MachineFunctionPass::getAnalysisUsage(AU);
}

char X86CSRegLivenessAnalysis::ID = 0;

bool X86CSRegLivenessAnalysis::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableCSRegLivenessAnalysis)
    return false;

  TRI = MF.getSubtarget().getRegisterInfo();
  MRI = &MF.getRegInfo();

  PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
  MBFI = &getAnalysis<MachineBlockFrequencyInfoWrapperPass>().getMBFI();

  calculateMachineFunctionCSRegUsage(MF);

  // Initialize the set of callee-saved registers for x86-64.
  CalleeSavedRegs = {
      X86::RBX, X86::RBP, X86::R12, X86::R13, X86::R14, X86::R15,
  };

  calculateCalleeSavedLiveness(MF);

  return false;
}

bool X86CSRegLivenessAnalysis::calculateMachineFunctionCSRegUsage(
    const MachineFunction &MF) {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  llvm::raw_os_ostream OS(std::cerr);
  OS.SetUnbuffered();
  llvm::StringRef cu_name = "";
  if (DISubprogram *subprogram = MF.getFunction().getSubprogram())
    if (llvm::DICompileUnit *comp_unit = subprogram->getUnit())
      cu_name = sys::path::remove_leading_dotslash(comp_unit->getFilename());
  OS << "IPRA: Function: " << MF.getName() << "[" << cu_name
     << "] CSRegUsage: ";
  if (!MFI.isCalleeSavedInfoValid()) {
    OS << " unavailable\n";
    return false;
  }

  for (const CalleeSavedInfo &Info : MFI.getCalleeSavedInfo())
    if (Info.isRestored())
      OS << " " << printReg(Info.getReg(), TRI);
  OS << "\n";

  if (PSI->isFunctionEntryHot(&MF)) {
    std::optional<llvm::Function::ProfileCount> oec =
        MF.getFunction().getEntryCount(false /*AllowSynthetic=false*/);
    OS << "IPRA: Function: " << MF.getName() << " IsFunctionEntryHot " <<
        (oec.has_value() ? oec->getCount() : 0);
  }
  return true;
}

// Main function to calculate callee-saved register liveness for the entire
// function.
void X86CSRegLivenessAnalysis::calculateCalleeSavedLiveness(
    MachineFunction &MF) {
  MF.RenumberBlocks();
  unsigned NumBlocks = MF.getNumBlockIDs();
  std::vector<MachineBasicBlock *> AllMBBs(NumBlocks);
  for (MachineBasicBlock &MBB : MF) {
    AllMBBs[MBB.getNumber()] = &MBB;
  }
  fullyRecomputeLiveIns(ArrayRef<MachineBasicBlock *>(&AllMBBs[0], NumBlocks));

  for (MachineBasicBlock &MBB : MF) {
    analyzeBasicBlock(MBB);
  }
}

// Analyzes a single basic block and updates the BlockLiveness vector
bool X86CSRegLivenessAnalysis::analyzeBasicBlock(MachineBasicBlock &MBB) {
  MachineFunction *MF = MBB.getParent();
  LivePhysRegs LiveRegs(*TRI);
  LiveRegs.addLiveOutsNoPristines(MBB);
  // LiveRegs.addLiveOuts(MBB);
  llvm::raw_os_ostream OS(std::cerr);
  OS.SetUnbuffered();
  // Now LiveRegs = MBB LiveOuts. Then we step backward through the block.
  int ii = 0;
  bool MBBDataPrinted = false;
  for (MachineInstr &MI : make_range(MBB.rbegin(), MBB.rend())) {
    ++ii;
    LiveRegs.stepBackward(MI);

    // Analyze callee-saved liveness around the call.
    // At this point, LiveRegs reflects the liveness *before* the call
    // instruction.
    if (MI.isCall() &&
        MI.getNumOperands() > 0 /* FEntry_Call has no operands */) {
      StringRef CalleeName = "";
      // Iterate over operands to find the call target
      const llvm::MachineOperand &MO = MI.getOperand(0);
      if (MO.isGlobal()) {
        const llvm::GlobalValue *GV = MO.getGlobal();
        if (const llvm::Function *F =
                llvm::dyn_cast<const llvm::Function>(GV)) {
          CalleeName = F->getName();
        } else if (const llvm::GlobalAlias *GA =
                       llvm::dyn_cast<llvm::GlobalAlias>(GV)) {
          // May be an alias to a function or to another alias
          const llvm::GlobalObject *GO = GA->getAliaseeObject();
          if (const llvm::Function *F =
                  llvm::dyn_cast_or_null<llvm::Function>(GO))
            CalleeName = F->getName();
        }
      } else if (MO.isSymbol()) {
        // Direct call to a symbol (likely an external function)
        CalleeName = MO.getSymbolName();
      }
      if (!CalleeName.empty()) {
        if (!MBBDataPrinted) {
          uint64_t CountValue;
          OS << "IPRA: MBB: " << MBB.getNumber()
             << " isHot: " << isHotBasicBlock(MBB, MBFI, PSI, CountValue) << " "
             << CountValue << "\n";
          MBBDataPrinted = true;
        }
        OS << "IPRA: call-site " << MF->getName() << "[" << MBB.getNumber()
           << "." << ii << "] calls " << CalleeName;
        OS << " CS regs live before insn:";
        for (MCPhysReg Reg : CalleeSavedRegs) {
          if (!LiveRegs.available(*MRI, Reg)) {
            OS << " " << printReg(Reg, TRI);
          }
        }
        OS << "\n";
        // OS << "  " << MI;
      }
      // end of "if (MI.isCall())"
    } else {
      // OS << "IPRA: CS regs live before insn:";
      // for (MCPhysReg Reg : CalleeSavedRegs) {
      //        // if (LiveRegs.contains(Reg)) {
      //        if (!LiveRegs.available(*MRI, Reg)) {
      //          OS << " " << printReg(Reg, TRI);
      //        }
      // }
      // OS << "\n";
      // OS << "  " << MI;
      ;
    }
  }
  return true;
}
}  // end of anonymous namespace

llvm::FunctionPass * llvm::createX86CSRegLivenessAnalysisPass() {
  return new X86CSRegLivenessAnalysis();
}

INITIALIZE_PASS_BEGIN(X86CSRegLivenessAnalysis, DEBUG_TYPE,
                      "Callee Saved Register Liveness Analysis Configure",
                      false, false)
INITIALIZE_PASS_END(X86CSRegLivenessAnalysis, DEBUG_TYPE,
                    "Callee Saved Register Liveness Analysis Configure", false,
                    false)
