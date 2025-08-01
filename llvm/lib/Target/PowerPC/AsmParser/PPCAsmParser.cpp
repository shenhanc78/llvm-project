//===-- PPCAsmParser.cpp - Parse PowerPC asm to MCInst instructions -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/PPCMCAsmInfo.h"
#include "MCTargetDesc/PPCMCTargetDesc.h"
#include "MCTargetDesc/PPCTargetStreamer.h"
#include "PPCInstrInfo.h"
#include "TargetInfo/PowerPCTargetInfo.h"
#include "llvm/ADT/Twine.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCParser/AsmLexer.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbolELF.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

DEFINE_PPC_REGCLASSES

// Evaluate an expression containing condition register
// or condition register field symbols.  Returns positive
// value on success, or -1 on error.
static int64_t
EvaluateCRExpr(const MCExpr *E) {
  switch (E->getKind()) {
  case MCExpr::Constant: {
    int64_t Res = cast<MCConstantExpr>(E)->getValue();
    return Res < 0 ? -1 : Res;
  }

  case MCExpr::SymbolRef: {
    const MCSymbolRefExpr *SRE = cast<MCSymbolRefExpr>(E);
    StringRef Name = SRE->getSymbol().getName();

    if (Name == "lt") return 0;
    if (Name == "gt") return 1;
    if (Name == "eq") return 2;
    if (Name == "so") return 3;
    if (Name == "un") return 3;

    if (Name == "cr0") return 0;
    if (Name == "cr1") return 1;
    if (Name == "cr2") return 2;
    if (Name == "cr3") return 3;
    if (Name == "cr4") return 4;
    if (Name == "cr5") return 5;
    if (Name == "cr6") return 6;
    if (Name == "cr7") return 7;

    return -1;
  }

  case MCExpr::Unary:
    return -1;

  case MCExpr::Binary: {
    const MCBinaryExpr *BE = cast<MCBinaryExpr>(E);
    int64_t LHSVal = EvaluateCRExpr(BE->getLHS());
    int64_t RHSVal = EvaluateCRExpr(BE->getRHS());
    int64_t Res;

    if (LHSVal < 0 || RHSVal < 0)
      return -1;

    switch (BE->getOpcode()) {
    default: return -1;
    case MCBinaryExpr::Add: Res = LHSVal + RHSVal; break;
    case MCBinaryExpr::Mul: Res = LHSVal * RHSVal; break;
    }

    return Res < 0 ? -1 : Res;
  }
  case MCExpr::Specifier:
    return -1;
  case MCExpr::Target:
    llvm_unreachable("unused by this backend");
  }

  llvm_unreachable("Invalid expression kind!");
}

namespace {

struct PPCOperand;

class PPCAsmParser : public MCTargetAsmParser {
  const bool IsPPC64;

  void Warning(SMLoc L, const Twine &Msg) { getParser().Warning(L, Msg); }

  bool isPPC64() const { return IsPPC64; }

  MCRegister matchRegisterName(int64_t &IntVal);

  bool parseRegister(MCRegister &Reg, SMLoc &StartLoc, SMLoc &EndLoc) override;
  ParseStatus tryParseRegister(MCRegister &Reg, SMLoc &StartLoc,
                               SMLoc &EndLoc) override;

  const MCExpr *extractSpecifier(const MCExpr *E,
                                 PPCMCExpr::Specifier &Variant);
  bool parseExpression(const MCExpr *&EVal);

  bool parseOperand(OperandVector &Operands);

  bool parseDirectiveWord(unsigned Size, AsmToken ID);
  bool parseDirectiveTC(unsigned Size, AsmToken ID);
  bool parseDirectiveMachine(SMLoc L);
  bool parseDirectiveAbiVersion(SMLoc L);
  bool parseDirectiveLocalEntry(SMLoc L);
  bool parseGNUAttribute(SMLoc L);

  bool matchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                               OperandVector &Operands, MCStreamer &Out,
                               uint64_t &ErrorInfo,
                               bool MatchingInlineAsm) override;

  void processInstruction(MCInst &Inst, const OperandVector &Ops);

  /// @name Auto-generated Match Functions
  /// {

#define GET_ASSEMBLER_HEADER
#include "PPCGenAsmMatcher.inc"

  /// }


public:
  PPCAsmParser(const MCSubtargetInfo &STI, MCAsmParser &,
               const MCInstrInfo &MII, const MCTargetOptions &Options)
      : MCTargetAsmParser(Options, STI, MII),
        IsPPC64(STI.getTargetTriple().isPPC64()) {
    // Initialize the set of available features.
    setAvailableFeatures(ComputeAvailableFeatures(STI.getFeatureBits()));
  }

  bool parseInstruction(ParseInstructionInfo &Info, StringRef Name,
                        SMLoc NameLoc, OperandVector &Operands) override;

  bool ParseDirective(AsmToken DirectiveID) override;

  unsigned validateTargetOperandClass(MCParsedAsmOperand &Op,
                                      unsigned Kind) override;

  const MCExpr *applySpecifier(const MCExpr *E, uint32_t,
                               MCContext &Ctx) override;
};

/// PPCOperand - Instances of this class represent a parsed PowerPC machine
/// instruction.
struct PPCOperand : public MCParsedAsmOperand {
  enum KindTy {
    Token,
    Immediate,
    ContextImmediate,
    Expression,
    TLSRegister
  } Kind;

  SMLoc StartLoc, EndLoc;
  bool IsPPC64;

  struct TokOp {
    const char *Data;
    unsigned Length;
  };

  struct ImmOp {
    int64_t Val;
    bool IsMemOpBase;
  };

  struct ExprOp {
    const MCExpr *Val;
    int64_t CRVal;     // Cached result of EvaluateCRExpr(Val)
  };

  struct TLSRegOp {
    const MCSymbolRefExpr *Sym;
  };

  union {
    struct TokOp Tok;
    struct ImmOp Imm;
    struct ExprOp Expr;
    struct TLSRegOp TLSReg;
  };

  PPCOperand(KindTy K) : Kind(K) {}

public:
  PPCOperand(const PPCOperand &o) : MCParsedAsmOperand() {
    Kind = o.Kind;
    StartLoc = o.StartLoc;
    EndLoc = o.EndLoc;
    IsPPC64 = o.IsPPC64;
    switch (Kind) {
    case Token:
      Tok = o.Tok;
      break;
    case Immediate:
    case ContextImmediate:
      Imm = o.Imm;
      break;
    case Expression:
      Expr = o.Expr;
      break;
    case TLSRegister:
      TLSReg = o.TLSReg;
      break;
    }
  }

  // Disable use of sized deallocation due to overallocation of PPCOperand
  // objects in CreateTokenWithStringCopy.
  void operator delete(void *p) { ::operator delete(p); }

  /// getStartLoc - Get the location of the first token of this operand.
  SMLoc getStartLoc() const override { return StartLoc; }

  /// getEndLoc - Get the location of the last token of this operand.
  SMLoc getEndLoc() const override { return EndLoc; }

  /// getLocRange - Get the range between the first and last token of this
  /// operand.
  SMRange getLocRange() const { return SMRange(StartLoc, EndLoc); }

  /// isPPC64 - True if this operand is for an instruction in 64-bit mode.
  bool isPPC64() const { return IsPPC64; }

  /// isMemOpBase - True if this operand is the base of a memory operand.
  bool isMemOpBase() const { return Kind == Immediate && Imm.IsMemOpBase; }

  int64_t getImm() const {
    assert(Kind == Immediate && "Invalid access!");
    return Imm.Val;
  }
  int64_t getImmS16Context() const {
    assert((Kind == Immediate || Kind == ContextImmediate) &&
           "Invalid access!");
    if (Kind == Immediate)
      return Imm.Val;
    return static_cast<int16_t>(Imm.Val);
  }
  int64_t getImmU16Context() const {
    assert((Kind == Immediate || Kind == ContextImmediate) &&
           "Invalid access!");
    return Imm.Val;
  }

  const MCExpr *getExpr() const {
    assert(Kind == Expression && "Invalid access!");
    return Expr.Val;
  }

  int64_t getExprCRVal() const {
    assert(Kind == Expression && "Invalid access!");
    return Expr.CRVal;
  }

  const MCExpr *getTLSReg() const {
    assert(Kind == TLSRegister && "Invalid access!");
    return TLSReg.Sym;
  }

  MCRegister getReg() const override { llvm_unreachable("Not implemented"); }

  unsigned getRegNum() const {
    assert(isRegNumber() && "Invalid access!");
    return (unsigned)Imm.Val;
  }

  unsigned getFpReg() const {
    assert(isEvenRegNumber() && "Invalid access!");
    return (unsigned)(Imm.Val >> 1);
  }

  unsigned getVSReg() const {
    assert(isVSRegNumber() && "Invalid access!");
    return (unsigned) Imm.Val;
  }

  unsigned getACCReg() const {
    assert(isACCRegNumber() && "Invalid access!");
    return (unsigned) Imm.Val;
  }

  unsigned getDMRROWReg() const {
    assert(isDMRROWRegNumber() && "Invalid access!");
    return (unsigned)Imm.Val;
  }

  unsigned getDMRROWpReg() const {
    assert(isDMRROWpRegNumber() && "Invalid access!");
    return (unsigned)Imm.Val;
  }

  unsigned getDMRReg() const {
    assert(isDMRRegNumber() && "Invalid access!");
    return (unsigned)Imm.Val;
  }

  unsigned getDMRpReg() const {
    assert(isDMRpRegNumber() && "Invalid access!");
    return (unsigned)Imm.Val;
  }

  unsigned getVSRpEvenReg() const {
    assert(isVSRpEvenRegNumber() && "Invalid access!");
    return (unsigned) Imm.Val >> 1;
  }

  unsigned getG8pReg() const {
    assert(isEvenRegNumber() && "Invalid access!");
    return (unsigned)Imm.Val;
  }

  unsigned getCCReg() const {
    assert(isCCRegNumber() && "Invalid access!");
    return (unsigned) (Kind == Immediate ? Imm.Val : Expr.CRVal);
  }

  unsigned getCRBit() const {
    assert(isCRBitNumber() && "Invalid access!");
    return (unsigned) (Kind == Immediate ? Imm.Val : Expr.CRVal);
  }

  unsigned getCRBitMask() const {
    assert(isCRBitMask() && "Invalid access!");
    return 7 - llvm::countr_zero<uint64_t>(Imm.Val);
  }

  bool isToken() const override { return Kind == Token; }
  bool isImm() const override {
    return Kind == Immediate || Kind == Expression;
  }
  bool isU1Imm() const { return Kind == Immediate && isUInt<1>(getImm()); }
  bool isU2Imm() const { return Kind == Immediate && isUInt<2>(getImm()); }
  bool isU3Imm() const { return Kind == Immediate && isUInt<3>(getImm()); }
  bool isU4Imm() const { return Kind == Immediate && isUInt<4>(getImm()); }
  bool isU5Imm() const { return Kind == Immediate && isUInt<5>(getImm()); }
  bool isS5Imm() const { return Kind == Immediate && isInt<5>(getImm()); }
  bool isU6Imm() const { return Kind == Immediate && isUInt<6>(getImm()); }
  bool isU6ImmX2() const { return Kind == Immediate &&
                                  isUInt<6>(getImm()) &&
                                  (getImm() & 1) == 0; }
  bool isU7Imm() const { return Kind == Immediate && isUInt<7>(getImm()); }
  bool isU7ImmX4() const { return Kind == Immediate &&
                                  isUInt<7>(getImm()) &&
                                  (getImm() & 3) == 0; }
  bool isU8Imm() const { return Kind == Immediate && isUInt<8>(getImm()); }
  bool isU8ImmX8() const { return Kind == Immediate &&
                                  isUInt<8>(getImm()) &&
                                  (getImm() & 7) == 0; }

  bool isU10Imm() const { return Kind == Immediate && isUInt<10>(getImm()); }
  bool isU12Imm() const { return Kind == Immediate && isUInt<12>(getImm()); }
  bool isU16Imm() const { return isExtImm<16>(/*Signed*/ false, 1); }
  bool isS16Imm() const { return isExtImm<16>(/*Signed*/ true, 1); }
  bool isS16ImmX4() const { return isExtImm<16>(/*Signed*/ true, 4); }
  bool isS16ImmX16() const { return isExtImm<16>(/*Signed*/ true, 16); }
  bool isS17Imm() const { return isExtImm<17>(/*Signed*/ true, 1); }

  bool isHashImmX8() const {
    // The Hash Imm form is used for instructions that check or store a hash.
    // These instructions have a small immediate range that spans between
    // -8 and -512.
    return (Kind == Immediate && getImm() <= -8 && getImm() >= -512 &&
            (getImm() & 7) == 0);
  }

  bool isS34ImmX16() const {
    return Kind == Expression ||
           (Kind == Immediate && isInt<34>(getImm()) && (getImm() & 15) == 0);
  }
  bool isS34Imm() const {
    // Once the PC-Rel ABI is finalized, evaluate whether a 34-bit
    // ContextImmediate is needed.
    return Kind == Expression || (Kind == Immediate && isInt<34>(getImm()));
  }

  bool isTLSReg() const { return Kind == TLSRegister; }
  bool isDirectBr() const {
    if (Kind == Expression)
      return true;
    if (Kind != Immediate)
      return false;
    // Operand must be 64-bit aligned, signed 27-bit immediate.
    if ((getImm() & 3) != 0)
      return false;
    if (isInt<26>(getImm()))
      return true;
    if (!IsPPC64) {
      // In 32-bit mode, large 32-bit quantities wrap around.
      if (isUInt<32>(getImm()) && isInt<26>(static_cast<int32_t>(getImm())))
        return true;
    }
    return false;
  }
  bool isCondBr() const { return Kind == Expression ||
                                 (Kind == Immediate && isInt<16>(getImm()) &&
                                  (getImm() & 3) == 0); }
  bool isImmZero() const { return Kind == Immediate && getImm() == 0; }
  bool isRegNumber() const { return Kind == Immediate && isUInt<5>(getImm()); }
  bool isACCRegNumber() const {
    return Kind == Immediate && isUInt<3>(getImm());
  }
  bool isDMRROWRegNumber() const {
    return Kind == Immediate && isUInt<6>(getImm());
  }
  bool isDMRROWpRegNumber() const {
    return Kind == Immediate && isUInt<5>(getImm());
  }
  bool isDMRRegNumber() const {
    return Kind == Immediate && isUInt<3>(getImm());
  }
  bool isDMRpRegNumber() const {
    return Kind == Immediate && isUInt<2>(getImm());
  }
  bool isVSRpEvenRegNumber() const {
    return Kind == Immediate && isUInt<6>(getImm()) && ((getImm() & 1) == 0);
  }
  bool isVSRegNumber() const {
    return Kind == Immediate && isUInt<6>(getImm());
  }
  bool isCCRegNumber() const { return (Kind == Expression
                                       && isUInt<3>(getExprCRVal())) ||
                                      (Kind == Immediate
                                       && isUInt<3>(getImm())); }
  bool isCRBitNumber() const { return (Kind == Expression
                                       && isUInt<5>(getExprCRVal())) ||
                                      (Kind == Immediate
                                       && isUInt<5>(getImm())); }

  bool isEvenRegNumber() const { return isRegNumber() && (getImm() & 1) == 0; }

  bool isCRBitMask() const {
    return Kind == Immediate && isUInt<8>(getImm()) &&
           llvm::has_single_bit<uint32_t>(getImm());
  }
  bool isATBitsAsHint() const { return false; }
  bool isMem() const override { return false; }
  bool isReg() const override { return false; }

  void addRegOperands(MCInst &Inst, unsigned N) const {
    llvm_unreachable("addRegOperands");
  }

  void addRegGPRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(RRegs[getRegNum()]));
  }

  void addRegGPRCNoR0Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(RRegsNoR0[getRegNum()]));
  }

  void addRegG8RCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(XRegs[getRegNum()]));
  }

  void addRegG8RCNoX0Operands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(XRegsNoX0[getRegNum()]));
  }

  void addRegG8pRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(XRegs[getG8pReg()]));
  }

  void addRegGxRCOperands(MCInst &Inst, unsigned N) const {
    if (isPPC64())
      addRegG8RCOperands(Inst, N);
    else
      addRegGPRCOperands(Inst, N);
  }

  void addRegGxRCNoR0Operands(MCInst &Inst, unsigned N) const {
    if (isPPC64())
      addRegG8RCNoX0Operands(Inst, N);
    else
      addRegGPRCNoR0Operands(Inst, N);
  }

  void addRegF4RCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(FRegs[getRegNum()]));
  }

  void addRegF8RCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(FRegs[getRegNum()]));
  }

  void addRegFpRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(FpRegs[getFpReg()]));
  }

  void addRegVFRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(VFRegs[getRegNum()]));
  }

  void addRegVRRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(VRegs[getRegNum()]));
  }

  void addRegVSRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(VSRegs[getVSReg()]));
  }

  void addRegVSFRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(VSFRegs[getVSReg()]));
  }

  void addRegVSSRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(VSSRegs[getVSReg()]));
  }

  void addRegSPE4RCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(RRegs[getRegNum()]));
  }

  void addRegSPERCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(SPERegs[getRegNum()]));
  }

  void addRegACCRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(ACCRegs[getACCReg()]));
  }

  void addRegDMRROWRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(DMRROWRegs[getDMRROWReg()]));
  }

  void addRegDMRROWpRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(DMRROWpRegs[getDMRROWpReg()]));
  }

  void addRegDMRRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(DMRRegs[getDMRReg()]));
  }

  void addRegDMRpRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(DMRpRegs[getDMRpReg()]));
  }

  void addRegWACCRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(WACCRegs[getACCReg()]));
  }

  void addRegWACC_HIRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(WACC_HIRegs[getACCReg()]));
  }

  void addRegVSRpRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(VSRpRegs[getVSRpEvenReg()]));
  }

  void addRegVSRpEvenRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(VSRpRegs[getVSRpEvenReg()]));
  }

  void addRegCRBITRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(CRBITRegs[getCRBit()]));
  }

  void addRegCRRCOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(CRRegs[getCCReg()]));
  }

  void addCRBitMaskOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createReg(CRRegs[getCRBitMask()]));
  }

  void addImmOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    if (Kind == Immediate)
      Inst.addOperand(MCOperand::createImm(getImm()));
    else
      Inst.addOperand(MCOperand::createExpr(getExpr()));
  }

  void addS16ImmOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    switch (Kind) {
      case Immediate:
        Inst.addOperand(MCOperand::createImm(getImm()));
        break;
      case ContextImmediate:
        Inst.addOperand(MCOperand::createImm(getImmS16Context()));
        break;
      default:
        Inst.addOperand(MCOperand::createExpr(getExpr()));
        break;
    }
  }

  void addU16ImmOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    switch (Kind) {
      case Immediate:
        Inst.addOperand(MCOperand::createImm(getImm()));
        break;
      case ContextImmediate:
        Inst.addOperand(MCOperand::createImm(getImmU16Context()));
        break;
      default:
        Inst.addOperand(MCOperand::createExpr(getExpr()));
        break;
    }
  }

  void addBranchTargetOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    if (Kind == Immediate)
      Inst.addOperand(MCOperand::createImm(getImm() / 4));
    else
      Inst.addOperand(MCOperand::createExpr(getExpr()));
  }

  void addTLSRegOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "Invalid number of operands!");
    Inst.addOperand(MCOperand::createExpr(getTLSReg()));
  }

  StringRef getToken() const {
    assert(Kind == Token && "Invalid access!");
    return StringRef(Tok.Data, Tok.Length);
  }

  void print(raw_ostream &OS, const MCAsmInfo &MAI) const override;

  static std::unique_ptr<PPCOperand> CreateToken(StringRef Str, SMLoc S,
                                                 bool IsPPC64) {
    auto Op = std::make_unique<PPCOperand>(Token);
    Op->Tok.Data = Str.data();
    Op->Tok.Length = Str.size();
    Op->StartLoc = S;
    Op->EndLoc = S;
    Op->IsPPC64 = IsPPC64;
    return Op;
  }

  static std::unique_ptr<PPCOperand>
  CreateTokenWithStringCopy(StringRef Str, SMLoc S, bool IsPPC64) {
    // Allocate extra memory for the string and copy it.
    // FIXME: This is incorrect, Operands are owned by unique_ptr with a default
    // deleter which will destroy them by simply using "delete", not correctly
    // calling operator delete on this extra memory after calling the dtor
    // explicitly.
    void *Mem = ::operator new(sizeof(PPCOperand) + Str.size());
    std::unique_ptr<PPCOperand> Op(new (Mem) PPCOperand(Token));
    Op->Tok.Data = reinterpret_cast<const char *>(Op.get() + 1);
    Op->Tok.Length = Str.size();
    std::memcpy(const_cast<char *>(Op->Tok.Data), Str.data(), Str.size());
    Op->StartLoc = S;
    Op->EndLoc = S;
    Op->IsPPC64 = IsPPC64;
    return Op;
  }

  static std::unique_ptr<PPCOperand> CreateImm(int64_t Val, SMLoc S, SMLoc E,
                                               bool IsPPC64,
                                               bool IsMemOpBase = false) {
    auto Op = std::make_unique<PPCOperand>(Immediate);
    Op->Imm.Val = Val;
    Op->Imm.IsMemOpBase = IsMemOpBase;
    Op->StartLoc = S;
    Op->EndLoc = E;
    Op->IsPPC64 = IsPPC64;
    return Op;
  }

  static std::unique_ptr<PPCOperand> CreateExpr(const MCExpr *Val, SMLoc S,
                                                SMLoc E, bool IsPPC64) {
    auto Op = std::make_unique<PPCOperand>(Expression);
    Op->Expr.Val = Val;
    Op->Expr.CRVal = EvaluateCRExpr(Val);
    Op->StartLoc = S;
    Op->EndLoc = E;
    Op->IsPPC64 = IsPPC64;
    return Op;
  }

  static std::unique_ptr<PPCOperand>
  CreateTLSReg(const MCSymbolRefExpr *Sym, SMLoc S, SMLoc E, bool IsPPC64) {
    auto Op = std::make_unique<PPCOperand>(TLSRegister);
    Op->TLSReg.Sym = Sym;
    Op->StartLoc = S;
    Op->EndLoc = E;
    Op->IsPPC64 = IsPPC64;
    return Op;
  }

  static std::unique_ptr<PPCOperand>
  CreateContextImm(int64_t Val, SMLoc S, SMLoc E, bool IsPPC64) {
    auto Op = std::make_unique<PPCOperand>(ContextImmediate);
    Op->Imm.Val = Val;
    Op->StartLoc = S;
    Op->EndLoc = E;
    Op->IsPPC64 = IsPPC64;
    return Op;
  }

  static std::unique_ptr<PPCOperand>
  CreateFromMCExpr(const MCExpr *Val, SMLoc S, SMLoc E, bool IsPPC64) {
    if (const MCConstantExpr *CE = dyn_cast<MCConstantExpr>(Val))
      return CreateImm(CE->getValue(), S, E, IsPPC64);

    if (const MCSymbolRefExpr *SRE = dyn_cast<MCSymbolRefExpr>(Val))
      if (getSpecifier(SRE) == PPC::S_TLS ||
          getSpecifier(SRE) == PPC::S_TLS_PCREL)
        return CreateTLSReg(SRE, S, E, IsPPC64);

    if (const auto *SE = dyn_cast<MCSpecifierExpr>(Val)) {
      int64_t Res;
      if (PPC::evaluateAsConstant(*SE, Res))
        return CreateContextImm(Res, S, E, IsPPC64);
    }

    return CreateExpr(Val, S, E, IsPPC64);
  }

private:
  template <unsigned Width>
  bool isExtImm(bool Signed, unsigned Multiple) const {
    switch (Kind) {
    default:
      return false;
    case Expression:
      return true;
    case Immediate:
    case ContextImmediate:
      if (Signed)
        return isInt<Width>(getImmS16Context()) &&
               (getImmS16Context() & (Multiple - 1)) == 0;
      else
        return isUInt<Width>(getImmU16Context()) &&
               (getImmU16Context() & (Multiple - 1)) == 0;
    }
  }
};

} // end anonymous namespace.

void PPCOperand::print(raw_ostream &OS, const MCAsmInfo &MAI) const {
  switch (Kind) {
  case Token:
    OS << "'" << getToken() << "'";
    break;
  case Immediate:
  case ContextImmediate:
    OS << getImm();
    break;
  case Expression:
    MAI.printExpr(OS, *getExpr());
    break;
  case TLSRegister:
    MAI.printExpr(OS, *getTLSReg());
    break;
  }
}

static void
addNegOperand(MCInst &Inst, MCOperand &Op, MCContext &Ctx) {
  if (Op.isImm()) {
    Inst.addOperand(MCOperand::createImm(-Op.getImm()));
    return;
  }
  const MCExpr *Expr = Op.getExpr();
  if (const MCUnaryExpr *UnExpr = dyn_cast<MCUnaryExpr>(Expr)) {
    if (UnExpr->getOpcode() == MCUnaryExpr::Minus) {
      Inst.addOperand(MCOperand::createExpr(UnExpr->getSubExpr()));
      return;
    }
  } else if (const MCBinaryExpr *BinExpr = dyn_cast<MCBinaryExpr>(Expr)) {
    if (BinExpr->getOpcode() == MCBinaryExpr::Sub) {
      const MCExpr *NE = MCBinaryExpr::createSub(BinExpr->getRHS(),
                                                 BinExpr->getLHS(), Ctx);
      Inst.addOperand(MCOperand::createExpr(NE));
      return;
    }
  }
  Inst.addOperand(MCOperand::createExpr(MCUnaryExpr::createMinus(Expr, Ctx)));
}

void PPCAsmParser::processInstruction(MCInst &Inst,
                                      const OperandVector &Operands) {
  int Opcode = Inst.getOpcode();
  switch (Opcode) {
  case PPC::DCBTx:
  case PPC::DCBTT:
  case PPC::DCBTSTx:
  case PPC::DCBTSTT: {
    MCInst TmpInst;
    TmpInst.setOpcode((Opcode == PPC::DCBTx || Opcode == PPC::DCBTT) ?
                      PPC::DCBT : PPC::DCBTST);
    TmpInst.addOperand(MCOperand::createImm(
      (Opcode == PPC::DCBTx || Opcode == PPC::DCBTSTx) ? 0 : 16));
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    Inst = TmpInst;
    break;
  }
  case PPC::DCBTCT:
  case PPC::DCBTDS: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::DCBT);
    TmpInst.addOperand(Inst.getOperand(2));
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    Inst = TmpInst;
    break;
  }
  case PPC::DCBTSTCT:
  case PPC::DCBTSTDS: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::DCBTST);
    TmpInst.addOperand(Inst.getOperand(2));
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    Inst = TmpInst;
    break;
  }
  case PPC::DCBFx:
  case PPC::DCBFL:
  case PPC::DCBFLP:
  case PPC::DCBFPS:
  case PPC::DCBSTPS: {
    int L = 0;
    if (Opcode == PPC::DCBFL)
      L = 1;
    else if (Opcode == PPC::DCBFLP)
      L = 3;
    else if (Opcode == PPC::DCBFPS)
      L = 4;
    else if (Opcode == PPC::DCBSTPS)
      L = 6;

    MCInst TmpInst;
    TmpInst.setOpcode(PPC::DCBF);
    TmpInst.addOperand(MCOperand::createImm(L));
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    Inst = TmpInst;
    break;
  }
  case PPC::LAx: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::LA);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(2));
    TmpInst.addOperand(Inst.getOperand(1));
    Inst = TmpInst;
    break;
  }
  case PPC::PLA8:
  case PPC::PLA: {
    MCInst TmpInst;
    TmpInst.setOpcode(Opcode == PPC::PLA ? PPC::PADDI : PPC::PADDI8);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(Inst.getOperand(2));
    Inst = TmpInst;
    break;
  }
  case PPC::PLA8pc:
  case PPC::PLApc: {
    MCInst TmpInst;
    TmpInst.setOpcode(Opcode == PPC::PLApc ? PPC::PADDIpc : PPC::PADDI8pc);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(MCOperand::createImm(0));
    TmpInst.addOperand(Inst.getOperand(1));
    Inst = TmpInst;
    break;
  }
  case PPC::SUBI: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::ADDI);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    addNegOperand(TmpInst, Inst.getOperand(2), getContext());
    Inst = TmpInst;
    break;
  }
  case PPC::PSUBI: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::PADDI);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    addNegOperand(TmpInst, Inst.getOperand(2), getContext());
    Inst = TmpInst;
    break;
  }
  case PPC::SUBIS: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::ADDIS);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    addNegOperand(TmpInst, Inst.getOperand(2), getContext());
    Inst = TmpInst;
    break;
  }
  case PPC::SUBIC: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::ADDIC);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    addNegOperand(TmpInst, Inst.getOperand(2), getContext());
    Inst = TmpInst;
    break;
  }
  case PPC::SUBIC_rec: {
    MCInst TmpInst;
    TmpInst.setOpcode(PPC::ADDIC_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    addNegOperand(TmpInst, Inst.getOperand(2), getContext());
    Inst = TmpInst;
    break;
  }
  case PPC::EXTLWI:
  case PPC::EXTLWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    int64_t B = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::EXTLWI ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(B));
    TmpInst.addOperand(MCOperand::createImm(0));
    TmpInst.addOperand(MCOperand::createImm(N - 1));
    Inst = TmpInst;
    break;
  }
  case PPC::EXTRWI:
  case PPC::EXTRWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    int64_t B = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::EXTRWI ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(B + N));
    TmpInst.addOperand(MCOperand::createImm(32 - N));
    TmpInst.addOperand(MCOperand::createImm(31));
    Inst = TmpInst;
    break;
  }
  case PPC::INSLWI:
  case PPC::INSLWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    int64_t B = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::INSLWI ? PPC::RLWIMI : PPC::RLWIMI_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(32 - B));
    TmpInst.addOperand(MCOperand::createImm(B));
    TmpInst.addOperand(MCOperand::createImm((B + N) - 1));
    Inst = TmpInst;
    break;
  }
  case PPC::INSRWI:
  case PPC::INSRWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    int64_t B = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::INSRWI ? PPC::RLWIMI : PPC::RLWIMI_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(32 - (B + N)));
    TmpInst.addOperand(MCOperand::createImm(B));
    TmpInst.addOperand(MCOperand::createImm((B + N) - 1));
    Inst = TmpInst;
    break;
  }
  case PPC::ROTRWI:
  case PPC::ROTRWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::ROTRWI ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(32 - N));
    TmpInst.addOperand(MCOperand::createImm(0));
    TmpInst.addOperand(MCOperand::createImm(31));
    Inst = TmpInst;
    break;
  }
  case PPC::SLWI:
  case PPC::SLWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::SLWI ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(N));
    TmpInst.addOperand(MCOperand::createImm(0));
    TmpInst.addOperand(MCOperand::createImm(31 - N));
    Inst = TmpInst;
    break;
  }
  case PPC::SRWI:
  case PPC::SRWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::SRWI ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(32 - N));
    TmpInst.addOperand(MCOperand::createImm(N));
    TmpInst.addOperand(MCOperand::createImm(31));
    Inst = TmpInst;
    break;
  }
  case PPC::CLRRWI:
  case PPC::CLRRWI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::CLRRWI ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(0));
    TmpInst.addOperand(MCOperand::createImm(0));
    TmpInst.addOperand(MCOperand::createImm(31 - N));
    Inst = TmpInst;
    break;
  }
  case PPC::CLRLSLWI:
  case PPC::CLRLSLWI_rec: {
    MCInst TmpInst;
    int64_t B = Inst.getOperand(2).getImm();
    int64_t N = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::CLRLSLWI ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(N));
    TmpInst.addOperand(MCOperand::createImm(B - N));
    TmpInst.addOperand(MCOperand::createImm(31 - N));
    Inst = TmpInst;
    break;
  }
  case PPC::EXTLDI:
  case PPC::EXTLDI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    int64_t B = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::EXTLDI ? PPC::RLDICR : PPC::RLDICR_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(B));
    TmpInst.addOperand(MCOperand::createImm(N - 1));
    Inst = TmpInst;
    break;
  }
  case PPC::EXTRDI:
  case PPC::EXTRDI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    int64_t B = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::EXTRDI ? PPC::RLDICL : PPC::RLDICL_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(B + N));
    TmpInst.addOperand(MCOperand::createImm(64 - N));
    Inst = TmpInst;
    break;
  }
  case PPC::INSRDI:
  case PPC::INSRDI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    int64_t B = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::INSRDI ? PPC::RLDIMI : PPC::RLDIMI_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(64 - (B + N)));
    TmpInst.addOperand(MCOperand::createImm(B));
    Inst = TmpInst;
    break;
  }
  case PPC::ROTRDI:
  case PPC::ROTRDI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::ROTRDI ? PPC::RLDICL : PPC::RLDICL_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(64 - N));
    TmpInst.addOperand(MCOperand::createImm(0));
    Inst = TmpInst;
    break;
  }
  case PPC::SLDI:
  case PPC::SLDI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::SLDI ? PPC::RLDICR : PPC::RLDICR_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(N));
    TmpInst.addOperand(MCOperand::createImm(63 - N));
    Inst = TmpInst;
    break;
  }
  case PPC::SUBPCIS: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(1).getImm();
    TmpInst.setOpcode(PPC::ADDPCIS);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(MCOperand::createImm(-N));
    Inst = TmpInst;
    break;
  }
  case PPC::SRDI:
  case PPC::SRDI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::SRDI ? PPC::RLDICL : PPC::RLDICL_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(64 - N));
    TmpInst.addOperand(MCOperand::createImm(N));
    Inst = TmpInst;
    break;
  }
  case PPC::CLRRDI:
  case PPC::CLRRDI_rec: {
    MCInst TmpInst;
    int64_t N = Inst.getOperand(2).getImm();
    TmpInst.setOpcode(Opcode == PPC::CLRRDI ? PPC::RLDICR : PPC::RLDICR_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(0));
    TmpInst.addOperand(MCOperand::createImm(63 - N));
    Inst = TmpInst;
    break;
  }
  case PPC::CLRLSLDI:
  case PPC::CLRLSLDI_rec: {
    MCInst TmpInst;
    int64_t B = Inst.getOperand(2).getImm();
    int64_t N = Inst.getOperand(3).getImm();
    TmpInst.setOpcode(Opcode == PPC::CLRLSLDI ? PPC::RLDIC : PPC::RLDIC_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(MCOperand::createImm(N));
    TmpInst.addOperand(MCOperand::createImm(B - N));
    Inst = TmpInst;
    break;
  }
  case PPC::RLWINMbm:
  case PPC::RLWINMbm_rec: {
    unsigned MB, ME;
    int64_t BM = Inst.getOperand(3).getImm();
    if (!isRunOfOnes(BM, MB, ME))
      break;

    MCInst TmpInst;
    TmpInst.setOpcode(Opcode == PPC::RLWINMbm ? PPC::RLWINM : PPC::RLWINM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(Inst.getOperand(2));
    TmpInst.addOperand(MCOperand::createImm(MB));
    TmpInst.addOperand(MCOperand::createImm(ME));
    Inst = TmpInst;
    break;
  }
  case PPC::RLWIMIbm:
  case PPC::RLWIMIbm_rec: {
    unsigned MB, ME;
    int64_t BM = Inst.getOperand(3).getImm();
    if (!isRunOfOnes(BM, MB, ME))
      break;

    MCInst TmpInst;
    TmpInst.setOpcode(Opcode == PPC::RLWIMIbm ? PPC::RLWIMI : PPC::RLWIMI_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(0)); // The tied operand.
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(Inst.getOperand(2));
    TmpInst.addOperand(MCOperand::createImm(MB));
    TmpInst.addOperand(MCOperand::createImm(ME));
    Inst = TmpInst;
    break;
  }
  case PPC::RLWNMbm:
  case PPC::RLWNMbm_rec: {
    unsigned MB, ME;
    int64_t BM = Inst.getOperand(3).getImm();
    if (!isRunOfOnes(BM, MB, ME))
      break;

    MCInst TmpInst;
    TmpInst.setOpcode(Opcode == PPC::RLWNMbm ? PPC::RLWNM : PPC::RLWNM_rec);
    TmpInst.addOperand(Inst.getOperand(0));
    TmpInst.addOperand(Inst.getOperand(1));
    TmpInst.addOperand(Inst.getOperand(2));
    TmpInst.addOperand(MCOperand::createImm(MB));
    TmpInst.addOperand(MCOperand::createImm(ME));
    Inst = TmpInst;
    break;
  }
  case PPC::MFTB: {
    if (getSTI().hasFeature(PPC::FeatureMFTB)) {
      assert(Inst.getNumOperands() == 2 && "Expecting two operands");
      Inst.setOpcode(PPC::MFSPR);
    }
    break;
  }
  }
}

static std::string PPCMnemonicSpellCheck(StringRef S, const FeatureBitset &FBS,
                                         unsigned VariantID = 0);

// Check that the register+immediate memory operand is in the right position and
// is expected by the instruction. Returns true if the memory operand syntax is
// valid; otherwise, returns false.
static bool validateMemOp(const OperandVector &Operands, bool isMemriOp) {
  for (size_t idx = 0; idx < Operands.size(); ++idx) {
    const PPCOperand &Op = static_cast<const PPCOperand &>(*Operands[idx]);
    if (Op.isMemOpBase() != (idx == 3 && isMemriOp))
      return false;
  }
  return true;
}

bool PPCAsmParser::matchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                                           OperandVector &Operands,
                                           MCStreamer &Out, uint64_t &ErrorInfo,
                                           bool MatchingInlineAsm) {
  MCInst Inst;
  const PPCInstrInfo *TII = static_cast<const PPCInstrInfo *>(&MII);

  switch (MatchInstructionImpl(Operands, Inst, ErrorInfo, MatchingInlineAsm)) {
  case Match_Success:
    if (!validateMemOp(Operands, TII->isMemriOp(Inst.getOpcode())))
      return Error(IDLoc, "invalid operand for instruction");
    // Post-process instructions (typically extended mnemonics)
    processInstruction(Inst, Operands);
    Inst.setLoc(IDLoc);
    Out.emitInstruction(Inst, getSTI());
    return false;
  case Match_MissingFeature:
    return Error(IDLoc, "instruction use requires an option to be enabled");
  case Match_MnemonicFail: {
    FeatureBitset FBS = ComputeAvailableFeatures(getSTI().getFeatureBits());
    std::string Suggestion = PPCMnemonicSpellCheck(
        ((PPCOperand &)*Operands[0]).getToken(), FBS);
    return Error(IDLoc, "invalid instruction" + Suggestion,
                 ((PPCOperand &)*Operands[0]).getLocRange());
  }
  case Match_InvalidOperand: {
    SMLoc ErrorLoc = IDLoc;
    if (ErrorInfo != ~0ULL) {
      if (ErrorInfo >= Operands.size())
        return Error(IDLoc, "too few operands for instruction");

      ErrorLoc = ((PPCOperand &)*Operands[ErrorInfo]).getStartLoc();
      if (ErrorLoc == SMLoc()) ErrorLoc = IDLoc;
    }

    return Error(ErrorLoc, "invalid operand for instruction");
  }
  }

  llvm_unreachable("Implement any new match types added!");
}

#define GET_REGISTER_MATCHER
#include "PPCGenAsmMatcher.inc"

MCRegister PPCAsmParser::matchRegisterName(int64_t &IntVal) {
  if (getParser().getTok().is(AsmToken::Percent))
    getParser().Lex(); // Eat the '%'.

  if (!getParser().getTok().is(AsmToken::Identifier))
    return MCRegister();

  // MatchRegisterName() expects lower-case registers, but we want to support
  // case-insensitive spelling.
  std::string NameBuf = getParser().getTok().getString().lower();
  StringRef Name(NameBuf);
  MCRegister RegNo = MatchRegisterName(Name);
  if (!RegNo)
    return RegNo;

  Name.substr(Name.find_first_of("1234567890")).getAsInteger(10, IntVal);

  // MatchRegisterName doesn't seem to have special handling for 64bit vs 32bit
  // register types.
  if (Name == "lr") {
    RegNo = isPPC64() ? PPC::LR8 : PPC::LR;
    IntVal = 8;
  } else if (Name == "ctr") {
    RegNo = isPPC64() ? PPC::CTR8 : PPC::CTR;
    IntVal = 9;
  } else if (Name == "vrsave")
    IntVal = 256;
  else if (Name.starts_with("r"))
    RegNo = isPPC64() ? XRegs[IntVal] : RRegs[IntVal];

  getParser().Lex();
  return RegNo;
}

bool PPCAsmParser::parseRegister(MCRegister &Reg, SMLoc &StartLoc,
                                 SMLoc &EndLoc) {
  if (!tryParseRegister(Reg, StartLoc, EndLoc).isSuccess())
    return TokError("invalid register name");
  return false;
}

ParseStatus PPCAsmParser::tryParseRegister(MCRegister &Reg, SMLoc &StartLoc,
                                           SMLoc &EndLoc) {
  const AsmToken &Tok = getParser().getTok();
  StartLoc = Tok.getLoc();
  EndLoc = Tok.getEndLoc();
  int64_t IntVal;
  if (!(Reg = matchRegisterName(IntVal)))
    return ParseStatus::NoMatch;
  return ParseStatus::Success;
}

// Extract the @l or @ha specifier from the expression, returning a modified
// expression with the specifier removed. Stores the extracted specifier in
// `Spec`. Reports an error if multiple specifiers are detected.
const MCExpr *PPCAsmParser::extractSpecifier(const MCExpr *E,
                                             PPCMCExpr::Specifier &Spec) {
  MCContext &Context = getParser().getContext();
  switch (E->getKind()) {
  case MCExpr::Constant:
    break;
  case MCExpr::Specifier: {
    // Detect error but do not return a modified expression.
    auto *TE = cast<MCSpecifierExpr>(E);
    Spec = TE->getSpecifier();
    (void)extractSpecifier(TE->getSubExpr(), Spec);
    Spec = PPC::S_None;
  } break;

  case MCExpr::SymbolRef: {
    const auto *SRE = cast<MCSymbolRefExpr>(E);
    switch (getSpecifier(SRE)) {
    case PPC::S_None:
    default:
      break;
    case PPC::S_LO:
    case PPC::S_HI:
    case PPC::S_HA:
    case PPC::S_HIGH:
    case PPC::S_HIGHA:
    case PPC::S_HIGHER:
    case PPC::S_HIGHERA:
    case PPC::S_HIGHEST:
    case PPC::S_HIGHESTA:
      if (Spec == PPC::S_None)
        Spec = getSpecifier(SRE);
      else
        Error(E->getLoc(), "cannot contain more than one relocation specifier");
      return MCSymbolRefExpr::create(&SRE->getSymbol(), Context);
    }
    break;
  }

  case MCExpr::Unary: {
    const MCUnaryExpr *UE = cast<MCUnaryExpr>(E);
    const MCExpr *Sub = extractSpecifier(UE->getSubExpr(), Spec);
    if (Spec != PPC::S_None)
      return MCUnaryExpr::create(UE->getOpcode(), Sub, Context);
    break;
  }

  case MCExpr::Binary: {
    const MCBinaryExpr *BE = cast<MCBinaryExpr>(E);
    const MCExpr *LHS = extractSpecifier(BE->getLHS(), Spec);
    const MCExpr *RHS = extractSpecifier(BE->getRHS(), Spec);
    if (Spec != PPC::S_None)
      return MCBinaryExpr::create(BE->getOpcode(), LHS, RHS, Context);
    break;
  }
  case MCExpr::Target:
    llvm_unreachable("unused by this backend");
  }

  return E;
}

/// This differs from the default "parseExpression" in that it handles
/// specifiers.
bool PPCAsmParser::parseExpression(const MCExpr *&EVal) {
  // (ELF Platforms)
  // Handle \code @l/@ha \endcode
  if (getParser().parseExpression(EVal))
    return true;

  uint16_t Spec = PPC::S_None;
  const MCExpr *E = extractSpecifier(EVal, Spec);
  if (Spec != PPC::S_None)
    EVal = MCSpecifierExpr::create(E, Spec, getParser().getContext());

  return false;
}

/// This handles registers in the form 'NN', '%rNN' for ELF platforms and
/// rNN for MachO.
bool PPCAsmParser::parseOperand(OperandVector &Operands) {
  MCAsmParser &Parser = getParser();
  SMLoc S = Parser.getTok().getLoc();
  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  const MCExpr *EVal;

  // Attempt to parse the next token as an immediate
  switch (getLexer().getKind()) {
  // Special handling for register names.  These are interpreted
  // as immediates corresponding to the register number.
  case AsmToken::Percent: {
    int64_t IntVal;
    if (!matchRegisterName(IntVal))
      return Error(S, "invalid register name");

    Operands.push_back(PPCOperand::CreateImm(IntVal, S, E, isPPC64()));
    return false;
  }
  case AsmToken::Identifier:
  case AsmToken::LParen:
  case AsmToken::Plus:
  case AsmToken::Minus:
  case AsmToken::Integer:
  case AsmToken::Dot:
  case AsmToken::Dollar:
  case AsmToken::Exclaim:
  case AsmToken::Tilde:
    if (!parseExpression(EVal))
      break;
    // Fall-through
    [[fallthrough]];
  default:
    return Error(S, "unknown operand");
  }

  // Push the parsed operand into the list of operands
  Operands.push_back(PPCOperand::CreateFromMCExpr(EVal, S, E, isPPC64()));

  // Check whether this is a TLS call expression
  const char TlsGetAddr[] = "__tls_get_addr";
  bool TlsCall = false;
  const MCExpr *TlsCallAddend = nullptr;
  if (auto *Ref = dyn_cast<MCSymbolRefExpr>(EVal)) {
    TlsCall = Ref->getSymbol().getName() == TlsGetAddr;
  } else if (auto *Bin = dyn_cast<MCBinaryExpr>(EVal);
             Bin && Bin->getOpcode() == MCBinaryExpr::Add) {
    if (auto *Ref = dyn_cast<MCSymbolRefExpr>(Bin->getLHS())) {
      TlsCall = Ref->getSymbol().getName() == TlsGetAddr;
      TlsCallAddend = Bin->getRHS();
    }
  }

  if (TlsCall && parseOptionalToken(AsmToken::LParen)) {
    const MCExpr *TLSSym;
    const SMLoc S2 = Parser.getTok().getLoc();
    if (parseExpression(TLSSym))
      return Error(S2, "invalid TLS call expression");
    E = Parser.getTok().getLoc();
    if (parseToken(AsmToken::RParen, "expected ')'"))
      return true;
    // PPC32 allows bl __tls_get_addr[+a](x@tlsgd)@plt+b. Parse "@plt[+b]".
    if (!isPPC64() && parseOptionalToken(AsmToken::At)) {
      AsmToken Tok = getTok();
      if (!(parseOptionalToken(AsmToken::Identifier) &&
            Tok.getString().compare_insensitive("plt") == 0))
        return Error(Tok.getLoc(), "expected 'plt'");
      EVal = MCSymbolRefExpr::create(getContext().getOrCreateSymbol(TlsGetAddr),
                                     PPC::S_PLT, getContext());
      if (parseOptionalToken(AsmToken::Plus)) {
        const MCExpr *Addend = nullptr;
        SMLoc EndLoc;
        if (parsePrimaryExpr(Addend, EndLoc))
          return true;
        if (TlsCallAddend) // __tls_get_addr+a(x@tlsgd)@plt+b
          TlsCallAddend =
              MCBinaryExpr::createAdd(TlsCallAddend, Addend, getContext());
        else // __tls_get_addr(x@tlsgd)@plt+b
          TlsCallAddend = Addend;
      }
      if (TlsCallAddend)
        EVal = MCBinaryExpr::createAdd(EVal, TlsCallAddend, getContext());
      // Add a __tls_get_addr operand with addend a, b, or a+b.
      Operands.back() = PPCOperand::CreateFromMCExpr(
          EVal, S, Parser.getTok().getLoc(), false);
    }

    Operands.push_back(PPCOperand::CreateFromMCExpr(TLSSym, S, E, isPPC64()));
  }

  // Otherwise, check for D-form memory operands
  if (!TlsCall && parseOptionalToken(AsmToken::LParen)) {
    S = Parser.getTok().getLoc();

    int64_t IntVal;
    switch (getLexer().getKind()) {
    case AsmToken::Percent: {
      if (!matchRegisterName(IntVal))
        return Error(S, "invalid register name");
      break;
    }
    case AsmToken::Integer:
      if (getParser().parseAbsoluteExpression(IntVal) || IntVal < 0 ||
          IntVal > 31)
        return Error(S, "invalid register number");
      break;
    case AsmToken::Identifier:
    default:
      return Error(S, "invalid memory operand");
    }

    E = Parser.getTok().getLoc();
    if (parseToken(AsmToken::RParen, "missing ')'"))
      return true;
    Operands.push_back(
        PPCOperand::CreateImm(IntVal, S, E, isPPC64(), /*IsMemOpBase=*/true));
  }

  return false;
}

/// Parse an instruction mnemonic followed by its operands.
bool PPCAsmParser::parseInstruction(ParseInstructionInfo &Info, StringRef Name,
                                    SMLoc NameLoc, OperandVector &Operands) {
  // The first operand is the token for the instruction name.
  // If the next character is a '+' or '-', we need to add it to the
  // instruction name, to match what TableGen is doing.
  std::string NewOpcode;
  if (parseOptionalToken(AsmToken::Plus)) {
    NewOpcode = std::string(Name);
    NewOpcode += '+';
    Name = NewOpcode;
  }
  if (parseOptionalToken(AsmToken::Minus)) {
    NewOpcode = std::string(Name);
    NewOpcode += '-';
    Name = NewOpcode;
  }
  // If the instruction ends in a '.', we need to create a separate
  // token for it, to match what TableGen is doing.
  size_t Dot = Name.find('.');
  StringRef Mnemonic = Name.slice(0, Dot);
  if (!NewOpcode.empty()) // Underlying memory for Name is volatile.
    Operands.push_back(
        PPCOperand::CreateTokenWithStringCopy(Mnemonic, NameLoc, isPPC64()));
  else
    Operands.push_back(PPCOperand::CreateToken(Mnemonic, NameLoc, isPPC64()));
  if (Dot != StringRef::npos) {
    SMLoc DotLoc = SMLoc::getFromPointer(NameLoc.getPointer() + Dot);
    StringRef DotStr = Name.substr(Dot);
    if (!NewOpcode.empty()) // Underlying memory for Name is volatile.
      Operands.push_back(
          PPCOperand::CreateTokenWithStringCopy(DotStr, DotLoc, isPPC64()));
    else
      Operands.push_back(PPCOperand::CreateToken(DotStr, DotLoc, isPPC64()));
  }

  // If there are no more operands then finish
  if (parseOptionalToken(AsmToken::EndOfStatement))
    return false;

  // Parse the first operand
  if (parseOperand(Operands))
    return true;

  while (!parseOptionalToken(AsmToken::EndOfStatement)) {
    if (parseToken(AsmToken::Comma) || parseOperand(Operands))
      return true;
  }

  // We'll now deal with an unfortunate special case: the syntax for the dcbt
  // and dcbtst instructions differs for server vs. embedded cores.
  //  The syntax for dcbt is:
  //    dcbt ra, rb, th [server]
  //    dcbt th, ra, rb [embedded]
  //  where th can be omitted when it is 0. dcbtst is the same. We take the
  //  server form to be the default, so swap the operands if we're parsing for
  //  an embedded core (they'll be swapped again upon printing).
  if (getSTI().hasFeature(PPC::FeatureBookE) &&
      Operands.size() == 4 &&
      (Name == "dcbt" || Name == "dcbtst")) {
    std::swap(Operands[1], Operands[3]);
    std::swap(Operands[2], Operands[1]);
  }

  // Handle base mnemonic for atomic loads where the EH bit is zero.
  if (Name == "lqarx" || Name == "ldarx" || Name == "lwarx" ||
      Name == "lharx" || Name == "lbarx") {
    if (Operands.size() != 5)
      return false;
    PPCOperand &EHOp = (PPCOperand &)*Operands[4];
    if (EHOp.isU1Imm() && EHOp.getImm() == 0)
      Operands.pop_back();
  }

  return false;
}

/// Parses the PPC specific directives
bool PPCAsmParser::ParseDirective(AsmToken DirectiveID) {
  StringRef IDVal = DirectiveID.getIdentifier();
  if (IDVal == ".word")
    parseDirectiveWord(2, DirectiveID);
  else if (IDVal == ".llong")
    parseDirectiveWord(8, DirectiveID);
  else if (IDVal == ".tc")
    parseDirectiveTC(isPPC64() ? 8 : 4, DirectiveID);
  else if (IDVal == ".machine")
    parseDirectiveMachine(DirectiveID.getLoc());
  else if (IDVal == ".abiversion")
    parseDirectiveAbiVersion(DirectiveID.getLoc());
  else if (IDVal == ".localentry")
    parseDirectiveLocalEntry(DirectiveID.getLoc());
  else if (IDVal.starts_with(".gnu_attribute"))
    parseGNUAttribute(DirectiveID.getLoc());
  else
    return true;
  return false;
}

///  ::= .word [ expression (, expression)* ]
bool PPCAsmParser::parseDirectiveWord(unsigned Size, AsmToken ID) {
  auto parseOp = [&]() -> bool {
    const MCExpr *Value;
    SMLoc ExprLoc = getParser().getTok().getLoc();
    if (getParser().parseExpression(Value))
      return true;
    if (const auto *MCE = dyn_cast<MCConstantExpr>(Value)) {
      assert(Size <= 8 && "Invalid size");
      uint64_t IntValue = MCE->getValue();
      if (!isUIntN(8 * Size, IntValue) && !isIntN(8 * Size, IntValue))
        return Error(ExprLoc, "literal value out of range for '" +
                                  ID.getIdentifier() + "' directive");
      getStreamer().emitIntValue(IntValue, Size);
    } else
      getStreamer().emitValue(Value, Size, ExprLoc);
    return false;
  };

  if (parseMany(parseOp))
    return addErrorSuffix(" in '" + ID.getIdentifier() + "' directive");
  return false;
}

///  ::= .tc [ symbol (, expression)* ]
bool PPCAsmParser::parseDirectiveTC(unsigned Size, AsmToken ID) {
  MCAsmParser &Parser = getParser();
  // Skip TC symbol, which is only used with XCOFF.
  while (getLexer().isNot(AsmToken::EndOfStatement)
         && getLexer().isNot(AsmToken::Comma))
    Parser.Lex();
  if (parseToken(AsmToken::Comma))
    return addErrorSuffix(" in '.tc' directive");

  // Align to word size.
  getParser().getStreamer().emitValueToAlignment(Align(Size));

  // Emit expressions.
  return parseDirectiveWord(Size, ID);
}

/// ELF platforms.
///  ::= .machine [ cpu | "push" | "pop" ]
bool PPCAsmParser::parseDirectiveMachine(SMLoc L) {
  MCAsmParser &Parser = getParser();
  if (Parser.getTok().isNot(AsmToken::Identifier) &&
      Parser.getTok().isNot(AsmToken::String))
    return Error(L, "unexpected token in '.machine' directive");

  StringRef CPU = Parser.getTok().getIdentifier();

  // FIXME: Right now, the parser always allows any available
  // instruction, so the .machine directive is not useful.
  // In the wild, any/push/pop/ppc64/altivec/power[4-9] are seen.

  Parser.Lex();

  if (parseToken(AsmToken::EndOfStatement))
    return addErrorSuffix(" in '.machine' directive");

  PPCTargetStreamer *TStreamer = static_cast<PPCTargetStreamer *>(
      getParser().getStreamer().getTargetStreamer());
  if (TStreamer != nullptr)
    TStreamer->emitMachine(CPU);

  return false;
}

///  ::= .abiversion constant-expression
bool PPCAsmParser::parseDirectiveAbiVersion(SMLoc L) {
  int64_t AbiVersion;
  if (check(getParser().parseAbsoluteExpression(AbiVersion), L,
            "expected constant expression") ||
      parseToken(AsmToken::EndOfStatement))
    return addErrorSuffix(" in '.abiversion' directive");

  PPCTargetStreamer *TStreamer = static_cast<PPCTargetStreamer *>(
      getParser().getStreamer().getTargetStreamer());
  if (TStreamer != nullptr)
    TStreamer->emitAbiVersion(AbiVersion);

  return false;
}

///  ::= .localentry symbol, expression
bool PPCAsmParser::parseDirectiveLocalEntry(SMLoc L) {
  StringRef Name;
  if (getParser().parseIdentifier(Name))
    return Error(L, "expected identifier in '.localentry' directive");

  MCSymbolELF *Sym = cast<MCSymbolELF>(getContext().getOrCreateSymbol(Name));
  const MCExpr *Expr;

  if (parseToken(AsmToken::Comma) ||
      check(getParser().parseExpression(Expr), L, "expected expression") ||
      parseToken(AsmToken::EndOfStatement))
    return addErrorSuffix(" in '.localentry' directive");

  PPCTargetStreamer *TStreamer = static_cast<PPCTargetStreamer *>(
      getParser().getStreamer().getTargetStreamer());
  if (TStreamer != nullptr)
    TStreamer->emitLocalEntry(Sym, Expr);

  return false;
}

bool PPCAsmParser::parseGNUAttribute(SMLoc L) {
  int64_t Tag;
  int64_t IntegerValue;
  if (!getParser().parseGNUAttribute(L, Tag, IntegerValue))
    return false;

  getParser().getStreamer().emitGNUAttribute(Tag, IntegerValue);

  return true;
}

/// Force static initialization.
extern "C" LLVM_ABI LLVM_EXTERNAL_VISIBILITY void
LLVMInitializePowerPCAsmParser() {
  RegisterMCAsmParser<PPCAsmParser> A(getThePPC32Target());
  RegisterMCAsmParser<PPCAsmParser> B(getThePPC32LETarget());
  RegisterMCAsmParser<PPCAsmParser> C(getThePPC64Target());
  RegisterMCAsmParser<PPCAsmParser> D(getThePPC64LETarget());
}

#define GET_MATCHER_IMPLEMENTATION
#define GET_MNEMONIC_SPELL_CHECKER
#include "PPCGenAsmMatcher.inc"

// Define this matcher function after the auto-generated include so we
// have the match class enum definitions.
unsigned PPCAsmParser::validateTargetOperandClass(MCParsedAsmOperand &AsmOp,
                                                  unsigned Kind) {
  // If the kind is a token for a literal immediate, check if our asm
  // operand matches. This is for InstAliases which have a fixed-value
  // immediate in the syntax.
  int64_t ImmVal;
  switch (Kind) {
    case MCK_0: ImmVal = 0; break;
    case MCK_1: ImmVal = 1; break;
    case MCK_2: ImmVal = 2; break;
    case MCK_3: ImmVal = 3; break;
    case MCK_4: ImmVal = 4; break;
    case MCK_5: ImmVal = 5; break;
    case MCK_6: ImmVal = 6; break;
    case MCK_7: ImmVal = 7; break;
    default: return Match_InvalidOperand;
  }

  PPCOperand &Op = static_cast<PPCOperand &>(AsmOp);
  if (Op.isU3Imm() && Op.getImm() == ImmVal)
    return Match_Success;

  return Match_InvalidOperand;
}

const MCExpr *PPCAsmParser::applySpecifier(const MCExpr *E, uint32_t Spec,
                                           MCContext &Ctx) {
  if (isa<MCConstantExpr>(E)) {
    switch (PPCMCExpr::Specifier(Spec)) {
    case PPC::S_LO:
    case PPC::S_HI:
    case PPC::S_HA:
    case PPC::S_HIGH:
    case PPC::S_HIGHA:
    case PPC::S_HIGHER:
    case PPC::S_HIGHERA:
    case PPC::S_HIGHEST:
    case PPC::S_HIGHESTA:
      break;
    default:
      return nullptr;
    }
  }

  return MCSpecifierExpr::create(E, Spec, Ctx);
}
