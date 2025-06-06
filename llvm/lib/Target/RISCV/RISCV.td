//===-- RISCV.td - Describe the RISC-V Target Machine ------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

include "llvm/Target/Target.td"

//===----------------------------------------------------------------------===//
// RISC-V subtarget features and instruction predicates.
//===----------------------------------------------------------------------===//

include "RISCVFeatures.td"

//===----------------------------------------------------------------------===//
// RISC-V profiles supported.
//===----------------------------------------------------------------------===//

include "RISCVProfiles.td"

//===----------------------------------------------------------------------===//
// Named operands for CSR instructions.
//===----------------------------------------------------------------------===//

include "RISCVSystemOperands.td"

//===----------------------------------------------------------------------===//
// Registers, calling conventions, instruction descriptions.
//===----------------------------------------------------------------------===//

include "RISCVRegisterInfo.td"
include "RISCVSchedule.td"
include "RISCVCallingConv.td"
include "RISCVInstrInfo.td"
include "GISel/RISCVRegisterBanks.td"

//===----------------------------------------------------------------------===//
// Instruction predicates
//===----------------------------------------------------------------------===//

include "RISCVInstrPredicates.td"

//===----------------------------------------------------------------------===//
// RISC-V macro fusions.
//===----------------------------------------------------------------------===//

include "RISCVMacroFusion.td"

//===----------------------------------------------------------------------===//
// RISC-V Scheduling Models
//===----------------------------------------------------------------------===//
include "RISCVSchedAndes45.td"
include "RISCVSchedGenericOOO.td"
include "RISCVSchedMIPSP8700.td"
include "RISCVSchedRocket.td"
include "RISCVSchedSiFive7.td"
include "RISCVSchedSiFiveP400.td"
include "RISCVSchedSiFiveP500.td"
include "RISCVSchedSiFiveP600.td"
include "RISCVSchedSiFiveP800.td"
include "RISCVSchedSpacemitX60.td"
include "RISCVSchedSyntacoreSCR1.td"
include "RISCVSchedSyntacoreSCR345.td"
include "RISCVSchedSyntacoreSCR7.td"
include "RISCVSchedTTAscalonD8.td"
include "RISCVSchedXiangShanNanHu.td"

//===----------------------------------------------------------------------===//
// RISC-V processors supported.
//===----------------------------------------------------------------------===//

include "RISCVProcessors.td"

//===----------------------------------------------------------------------===//
// Pfm Counters
//===----------------------------------------------------------------------===//

include "RISCVPfmCounters.td"

//===----------------------------------------------------------------------===//
// Define the RISC-V target.
//===----------------------------------------------------------------------===//

def RISCVInstrInfo : InstrInfo {
  let guessInstructionProperties = 0;
}

def RISCVAsmParser : AsmParser {
  let ShouldEmitMatchRegisterAltName = 1;
  let AllowDuplicateRegisterNames = 1;
}

def RISCVAsmWriter : AsmWriter {
  int PassSubtarget = 1;
}

def RISCV : Target {
  let InstructionSet = RISCVInstrInfo;
  let AssemblyParsers = [RISCVAsmParser];
  let AssemblyWriters = [RISCVAsmWriter];
  let AllowRegisterRenaming = 1;
}
