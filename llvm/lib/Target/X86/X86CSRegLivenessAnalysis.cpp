#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <system_error>  // NOLINT
#include <vector>

#include "llvm/ADT/iterator_range.h"
#include "llvm/ADT/StringRef.h"
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
#include "llvm/IR/SymbolTableListTraits.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Pass.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"

#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"


// For X86-64, include the X86.h header to get the register enums.
#include "llvm/Target/TargetOptions.h"
#include "llvm/MC/MCTargetOptions.h"

#define DEBUG_TYPE "cs-reg-liveness"

// This file contains a list of function symbols that we would like to
// optimize, each symbol in a separate line

namespace {

using ::llvm::AnalysisUsage;
using ::llvm::ArrayRef;
using ::llvm::CalleeSavedInfo;
using ::llvm::DICompileUnit;
using ::llvm::DISubprogram;
using ::llvm::Function;
using ::llvm::LivePhysRegs;
using ::llvm::MachineBasicBlock;
using ::llvm::MachineBlockFrequencyInfo;
using ::llvm::MachineBlockFrequencyInfoWrapperPass;
using ::llvm::MachineFrameInfo;
using ::llvm::MachineFunction;
using ::llvm::MachineFunctionPass;
using ::llvm::MachineInstr;
using ::llvm::MachineModuleInfoWrapperPass;
using ::llvm::MachineRegisterInfo;
using ::llvm::MCPhysReg;
using ::llvm::ProfileSummaryInfo;
using ::llvm::ProfileSummaryInfoWrapperPass;
using ::llvm::StringRef;
using ::llvm::sys::path::remove_leading_dotslash;

using ::llvm::X86RegisterInfo;
using ::llvm::X86InstrInfo;
using ::llvm::X86Subtarget;

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
                             status)) { // Negate to check for success.
    if (llvm::sys::fs::exists(status) && llvm::sys::fs::is_directory(status)) {
      return true; // Directory already exists
    }
  }

  // Directory doesn't exist, create it
  std::error_code ec = llvm::sys::fs::create_directories(directoryPath);
  if (ec) {
    llvm::errs() << "Error creating directory " << directoryPath << ": "
                 << ec.message() << "\n";
    return false; // Failed to create directory
  }
  return true; // Directory created successfully
}

}  // namespace

static bool isHotBasicBlock(const MachineBasicBlock &MBB,
                            const MachineBlockFrequencyInfo *MBFI,
                            const ProfileSummaryInfo *PSI, uint64_t &CountVal) {
  std::optional<uint64_t> Count = MBFI->getBlockProfileCount(&MBB);
  CountVal = (Count.has_value() ? Count.value() : 0);
  return Count.has_value() && PSI->isHotCount(*Count);
}

static std::string getFunctionModuleName(const Function &F) {
  StringRef cu_name = "";
  if (DISubprogram *subprogram = F.getSubprogram())
    if (DICompileUnit *comp_unit = subprogram->getUnit())
      cu_name = remove_leading_dotslash(comp_unit->getFilename());
  return cu_name.str();
}

class X86CSRegLivenessAnalysis : public MachineFunctionPass {
 public:
  static char ID;
  X86CSRegLivenessAnalysis()
      : MachineFunctionPass(ID), OutputFilename(""), OS(nullptr) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override;

  bool doInitialization(llvm::Module &) override {
    if (!EnableCSRegLivenessAnalysis) {
      OS = nullptr;
      OutputFilename = "";
      return false;
    }
    if (!ensureDirectoryExists(CSRegLivenessAnalysisOutputDir)) {
      llvm::report_fatal_error(llvm::StringRef("ensureDirectoryExists failed"));
    }
    llvm::SmallString<128> OutputPrefix =
        llvm::StringRef(CSRegLivenessAnalysisOutputDir);
    llvm::sys::path::append(OutputPrefix, "ipra_analysis_");
    OutputFilename = generateRandomFilename(std::string(OutputPrefix));
    std::cerr << "Output: " << OutputFilename << "\n";
    std::error_code EC;
    OS = new llvm::raw_fd_ostream(
        OutputFilename, EC, llvm::sys::fs::CreationDisposition::CD_CreateNew,
        llvm::sys::fs::FileAccess::FA_Write, llvm::sys::fs::OpenFlags::OF_Text);
    if (EC) {
      llvm::report_fatal_error(llvm::StringRef("Could not open file: ") +
                               EC.message());
    }
    return false;  // Module is not changed.
  }

  bool doFinalization(llvm::Module &) override {
    if (!OS)
      return false;

    OS->flush();
    delete OS;
    OS = nullptr;
    OutputFilename = "";
    return false;  // Module is not changed.
  }

 private:
  const X86RegisterInfo *TRI;
  const X86InstrInfo *TII;
  const MachineRegisterInfo *MRI;
  const ProfileSummaryInfo *PSI;
  const MachineBlockFrequencyInfo *MBFI;

  std::string OutputFilename;
  llvm::raw_ostream *OS;

  // Set of callee-saved registers on x86-64
  std::vector<MCPhysReg> CalleeSavedRegs;

  bool calculateMachineFunctionCSRegUsage(const MachineFunction &MF);
  void calculateCalleeSavedLiveness(MachineFunction &MF);
  bool analyzeBasicBlock(MachineBasicBlock &MBB);

  std::string FuncModuleName;
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

  TRI = MF.getSubtarget<X86Subtarget>().getRegisterInfo();
  TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();
  MRI = &MF.getRegInfo();

  PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
  MBFI = &getAnalysis<MachineBlockFrequencyInfoWrapperPass>().getMBFI();

  FuncModuleName = getFunctionModuleName(MF.getFunction());

  calculateMachineFunctionCSRegUsage(MF);

  // Initialize the set of callee-saved registers for x86-64.
  CalleeSavedRegs = {
      llvm::X86::RBX, llvm::X86::RBP, llvm::X86::R12,
      llvm::X86::R13, llvm::X86::R14, llvm::X86::R15,
  };

  calculateCalleeSavedLiveness(MF);

  return false;
}

bool X86CSRegLivenessAnalysis::calculateMachineFunctionCSRegUsage(
    const MachineFunction &MF) {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  (*OS) <<  "IPRA: Function: " << MF.getName() << "[" << FuncModuleName << "]";
  (*OS) <<  " CallingConv: "
     << static_cast<unsigned int>(MF.getFunction().getCallingConv());

  (*OS) <<  " CSRegUsage: ";
  if (!MFI.isCalleeSavedInfoValid()) {
    (*OS) <<  "unavailable\n";
    return false;
  }
  int t = 0;
  for (const CalleeSavedInfo &Info : MFI.getCalleeSavedInfo()) {
    if (Info.isRestored()) {
      if (t) (*OS) <<  " ";
      (*OS) <<  printReg(Info.getReg(), TRI);
      ++t;
    }
  }

  if (PSI->isFunctionEntryHot(&MF)) {
    std::optional<Function::ProfileCount> oec =
        MF.getFunction().getEntryCount(/*AllowSynthetic=*/true);
    (*OS) <<  " IsFunctionEntryHot: 1 EntryCount: "
       << (oec.has_value() ? oec->getCount() : 0);
  } else {
    (*OS) <<  " IsFunctionEntryHot: 0";
  }
  (*OS) <<  "\n";

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
  // Now LiveRegs = MBB LiveOuts. Then we step backward through the block.
  int ii = 0;
  uint64_t MBBCount;
  bool MBBIsHot = isHotBasicBlock(MBB, MBFI, PSI, MBBCount);
  bool MBBDataPrinted = false;
  for (MachineInstr &MI : make_range(MBB.rbegin(), MBB.rend())) {
    ++ii;
    LiveRegs.stepBackward(MI);

    bool IsTailCall = TII->isTailCall(MI);
    // Analyze callee-saved liveness around the call.
    // At this point, LiveRegs reflects the liveness *before* the call
    // instruction.
    if ((MI.isCall() || IsTailCall) &&
        MI.getNumOperands() > 0 /* FEntry_Call has no operands */) {
      StringRef CalleeName = "";
      std::string CalleeModuleName = "";
      // Iterate over operands to find the call target
      const llvm::MachineOperand &MO = MI.getOperand(0);
      if (MO.isGlobal()) {
        const llvm::GlobalValue *GV = MO.getGlobal();
        if (const llvm::Function *F =
                llvm::dyn_cast<const llvm::Function>(GV)) {
          CalleeName = F->getName();
          CalleeModuleName = getFunctionModuleName(*F);
        } else if (const llvm::GlobalAlias *GA =
                       llvm::dyn_cast<llvm::GlobalAlias>(GV)) {
          // May be an alias to a function or to another alias
          if (const llvm::GlobalObject *GO = GA->getAliaseeObject()) {
            if (const llvm::Function *F =
                    llvm::dyn_cast_or_null<llvm::Function>(GO)) {
              CalleeName = F->getName();
              CalleeModuleName = getFunctionModuleName(*F);
            }
          }
        }
      } else if (MO.isSymbol()) {
        // Direct call to a symbol (likely an external function).
        CalleeName = MO.getSymbolName();
      }
      if (!CalleeName.empty()) {
        if (!MBBDataPrinted) {
          (*OS) <<  "IPRA: Function: " << MF->getName() << "[" << FuncModuleName
             << "] MBB: " << MBB.getNumber() << " IsMBBHot: " << MBBIsHot
             << " MBBCount: " << MBBCount << "\n";
          MBBDataPrinted = true;
        }
        (*OS) <<  "IPRA: Function: " << MF->getName() << "[" << FuncModuleName
           << "] " << "Calls: " << CalleeName << "[" << CalleeModuleName
           << "] IsTailCall: " << (IsTailCall ? 1 : 0)
           << " CallSiteLoc: " << MBB.getNumber() << "." << ii
           << " LivingCSRegs: ";
        int t = 0;
        for (MCPhysReg Reg : CalleeSavedRegs) {
          if (!LiveRegs.available(*MRI, Reg)) {
            if (t)
              (*OS) <<  " ";
            (*OS) <<  printReg(Reg, TRI);
            ++t;
          }
        }
        (*OS) <<  "\n";
        // (*OS) <<  "  " << MI;
      }
      // end of "if (MI.isCall())"
    } else {
      // (*OS) <<  "IPRA: CS regs live before insn:";
      // for (MCPhysReg Reg : CalleeSavedRegs) {
      //        // if (LiveRegs.contains(Reg)) {
      //        if (!LiveRegs.available(*MRI, Reg)) {
      //          (*OS) <<  " " << printReg(Reg, TRI);
      //        }
      // }
      // (*OS) <<  "\n";
      // (*OS) <<  "  " << MI;
      {}
    }
  }
  return true;
}
}  // end of anonymous namespace

llvm::FunctionPass * llvm::createX86CSRegLivenessAnalysisPass() {
  return new X86CSRegLivenessAnalysis();
}

using namespace llvm;  // NOLINT

INITIALIZE_PASS_BEGIN(X86CSRegLivenessAnalysis, DEBUG_TYPE,
                      "Callee Saved Register Liveness Analysis Configure",
                      false, false)

INITIALIZE_PASS_END(X86CSRegLivenessAnalysis, DEBUG_TYPE,
                    "Callee Saved Register Liveness Analysis Configure", false,
                    false)
