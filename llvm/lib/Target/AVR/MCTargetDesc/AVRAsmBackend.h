//===-- AVRAsmBackend.h - AVR Asm Backend  --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// \file The AVR assembly backend implementation.
//
//===----------------------------------------------------------------------===//
//

#ifndef LLVM_AVR_ASM_BACKEND_H
#define LLVM_AVR_ASM_BACKEND_H

#include "MCTargetDesc/AVRFixupKinds.h"

#include "llvm/MC/MCAsmBackend.h"
#include "llvm/TargetParser/Triple.h"

namespace llvm {

class MCAssembler;
class MCContext;
struct MCFixupKindInfo;

/// Utilities for manipulating generated AVR machine code.
class AVRAsmBackend : public MCAsmBackend {
public:
  AVRAsmBackend(Triple::OSType OSType)
      : MCAsmBackend(llvm::endianness::little), OSType(OSType) {}

  void adjustFixupValue(const MCFixup &Fixup, const MCValue &Target,
                        uint64_t &Value, MCContext *Ctx = nullptr) const;

  std::unique_ptr<MCObjectTargetWriter>
  createObjectTargetWriter() const override;

  void applyFixup(const MCFragment &, const MCFixup &, const MCValue &Target,
                  uint8_t *Data, uint64_t Value, bool IsResolved) override;

  std::optional<MCFixupKind> getFixupKind(StringRef Name) const override;
  MCFixupKindInfo getFixupKindInfo(MCFixupKind Kind) const override;

  bool writeNopData(raw_ostream &OS, uint64_t Count,
                    const MCSubtargetInfo *STI) const override;

  bool forceRelocation(const MCFragment &F, const MCFixup &Fixup,
                       const MCValue &Target);

private:
  Triple::OSType OSType;
};

} // end namespace llvm

#endif // LLVM_AVR_ASM_BACKEND_H
