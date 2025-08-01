//=== - AArch64AttributeParser.h-AArch64 Attribute Information Printer - ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===--------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_AARCH64ATTRIBUTEPARSER_H
#define LLVM_SUPPORT_AARCH64ATTRIBUTEPARSER_H

#include "llvm/Support/Compiler.h"
#include "llvm/Support/ELFAttrParserExtended.h"
#include "llvm/Support/ELFAttributes.h"

namespace llvm {

class AArch64AttributeParser : public ELFExtendedAttrParser {
  LLVM_ABI static std::vector<SubsectionAndTagToTagName> &returnTagsNamesMap();

public:
  AArch64AttributeParser(ScopedPrinter *Sw)
      : ELFExtendedAttrParser(Sw, returnTagsNamesMap()) {}
  AArch64AttributeParser()
      : ELFExtendedAttrParser(nullptr, returnTagsNamesMap()) {}
};

// Used for extracting AArch64 Build Attributes
struct AArch64BuildAttrSubsections {
  struct PauthSubSection {
    uint64_t TagPlatform = 0;
    uint64_t TagSchema = 0;
  } Pauth;
  uint32_t AndFeatures = 0;
};

LLVM_ABI AArch64BuildAttrSubsections
extractBuildAttributesSubsections(const llvm::AArch64AttributeParser &);
} // namespace llvm

#endif // LLVM_SUPPORT_AARCH64ATTRIBUTEPARSER_H
