//===-- AArch64GuardHighBit.cpp - Guard high bit on indirect branches -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This pass guards forward-edge indirect branches and calls (BLR*, BR*, and
// non-LR RET) by inserting a GUARD_HIGH_BIT_CHECK pseudo-instruction right
// before the indirect branch. AsmPrinter lowers this pseudo into:
//
//   tbnz xN, #Bit, .Ltmp
//   brk  #0x1
// .Ltmp:
//   blr  xN   (or br xN / ret xN)
//
// Because TBNZ tests a single bit without modifying registers or NZCV flags,
// this enforces address-space confinement (e.g., keeping upper-address-space
// indirect branches out of a lower restricted user address space when
// Bit == 47) in 8 bytes with zero scratch registers and compatible with
// AArch64 TBI.
//
//===----------------------------------------------------------------------===//

#include "AArch64.h"
#include "AArch64InstrInfo.h"
#include "AArch64Subtarget.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Support/Debug.h"
#include <optional>

using namespace llvm;

#define DEBUG_TYPE "aarch64-guard-high-bit"
#define AARCH64_GUARD_HIGH_BIT_NAME "AArch64 Guard High Bit"

namespace {

class AArch64GuardHighBitImpl {
public:
  bool run(MachineFunction &MF);

private:
  std::optional<unsigned> getGuardBit(const MachineFunction &MF) const;
  std::optional<Register> getGuardedTargetReg(const MachineInstr &MI) const;
  void splitBeforeTerminator(MachineFunction &MF, MachineBasicBlock &MBB,
                             MachineBasicBlock::iterator TermIt,
                             const TargetRegisterInfo *TRI);
};

class AArch64GuardHighBitLegacy : public MachineFunctionPass {
public:
  static char ID;
  AArch64GuardHighBitLegacy() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override {
    return AArch64GuardHighBitImpl().run(MF);
  }

  MachineFunctionProperties getRequiredProperties() const override {
    return MachineFunctionProperties().setNoVRegs();
  }

  StringRef getPassName() const override { return AARCH64_GUARD_HIGH_BIT_NAME; }
};

} // end anonymous namespace

char AArch64GuardHighBitLegacy::ID = 0;

INITIALIZE_PASS(AArch64GuardHighBitLegacy, DEBUG_TYPE,
                AARCH64_GUARD_HIGH_BIT_NAME, false, false)

FunctionPass *llvm::createAArch64GuardHighBitPass() {
  return new AArch64GuardHighBitLegacy();
}

PreservedAnalyses
AArch64GuardHighBitPass::run(MachineFunction &MF,
                             MachineFunctionAnalysisManager &MFAM) {
  if (!AArch64GuardHighBitImpl().run(MF))
    return PreservedAnalyses::all();
  return getMachineFunctionPassPreservedAnalyses();
}

std::optional<unsigned>
AArch64GuardHighBitImpl::getGuardBit(const MachineFunction &MF) const {
  const Function &F = MF.getFunction();
  Attribute Attr = F.getFnAttribute("guard-high-bit");
  if (Attr.isValid()) {
    StringRef Val = Attr.getValueAsString();
    if (Val == "none")
      return std::nullopt;
    unsigned Bit = 0;
    if (!Val.getAsInteger(10, Bit) && Bit < 64)
      return Bit;
    MF.getContext().reportError(
        SMLoc(), "invalid 'guard-high-bit' function attribute value '" + Val +
                     "' (expected 'none' or integer in [0, 63])");
    return std::nullopt;
  }

  int CLBit = MF.getSubtarget<AArch64Subtarget>().getCLOpts().guard_high_bit;
  if (CLBit < 0)
    return std::nullopt;
  if (CLBit >= 64) {
    MF.getContext().reportError(
        SMLoc(),
        "invalid -aarch64-guard-high-bit value (expected -1 or 0..63)");
    return std::nullopt;
  }
  return static_cast<unsigned>(CLBit);
}

static std::optional<Register> getSingleInstrTargetReg(const MachineInstr &MI) {
  switch (MI.getOpcode()) {
  case AArch64::BLR:
  case AArch64::BLRNoIP:
  case AArch64::BLRAA:
  case AArch64::BLRAB:
  case AArch64::BLRAAZ:
  case AArch64::BLRABZ:
  case AArch64::BLRA:
  case AArch64::BR:
  case AArch64::BRAA:
  case AArch64::BRAB:
  case AArch64::BRAAZ:
  case AArch64::BRABZ:
  case AArch64::BRA:
  case AArch64::TCRETURNri:
  case AArch64::TCRETURNrix16x17:
  case AArch64::TCRETURNrix17:
  case AArch64::TCRETURNrinotx16:
  case AArch64::TCRETURNriALL:
  case AArch64::AUTH_TCRETURN:
  case AArch64::AUTH_TCRETURN_BTI:
    return MI.getOperand(0).getReg();
  case AArch64::RET: {
    Register Reg = MI.getOperand(0).getReg();
    // Standard return via X30 (LR) is backward-edge and covered by
    // ShadowCallStack / PAC-RET; non-LR RET acts as an indirect jump gadget.
    if (Reg != AArch64::LR)
      return Reg;
    return std::nullopt;
  }
  default:
    return std::nullopt;
  }
}

std::optional<Register>
AArch64GuardHighBitImpl::getGuardedTargetReg(const MachineInstr &MI) const {
  if (!MI.isBundle())
    return getSingleInstrTargetReg(MI);

  // Inspect bundled instructions (e.g. Objective-C BLR_RVMARKER bundles).
  const MachineBasicBlock *MBB = MI.getParent();
  auto I = std::next(MI.getIterator());
  while (I != MBB->instr_end() && I->isInsideBundle()) {
    if (I->getOpcode() == AArch64::TLSDESCCALL ||
        I->getOpcode() == AArch64::TLSAUTHDESCCALL)
      return std::nullopt;
    if (auto Reg = getSingleInstrTargetReg(*I))
      return Reg;
    ++I;
  }
  return std::nullopt;
}

void AArch64GuardHighBitImpl::splitBeforeTerminator(
    MachineFunction &MF, MachineBasicBlock &MBB,
    MachineBasicBlock::iterator TermIt, const TargetRegisterInfo *TRI) {
  MachineBasicBlock *NewMBB = MF.CreateMachineBasicBlock(MBB.getBasicBlock());
  NewMBB->setSectionID(MBB.getSectionID());
  MF.insert(std::next(MBB.getIterator()), NewMBB);
  NewMBB->splice(NewMBB->end(), &MBB, TermIt, MBB.end());

  // Determine which successors are referenced by the terminators remaining in
  // MBB versus the indirect terminator moved into NewMBB.
  SmallPtrSet<MachineBasicBlock *, 4> KeptOnOrig;
  for (auto I = MBB.getFirstTerminator(); I != MBB.end(); ++I)
    for (const MachineOperand &MO : I->operands())
      if (MO.isMBB())
        KeptOnOrig.insert(MO.getMBB());

  SmallPtrSet<MachineBasicBlock *, 4> KeptOnNew;
  for (const MachineInstr &MovedMI : *NewMBB)
    for (const MachineOperand &MO : MovedMI.operands())
      if (MO.isMBB())
        KeptOnNew.insert(MO.getMBB());

  SmallVector<MachineBasicBlock *, 8> OrigSuccs(MBB.succ_begin(),
                                                MBB.succ_end());
  for (MachineBasicBlock *Succ : OrigSuccs) {
    if (!KeptOnOrig.contains(Succ)) {
      NewMBB->addSuccessor(Succ);
      MBB.removeSuccessor(Succ);
    } else if (KeptOnNew.contains(Succ)) {
      NewMBB->addSuccessor(Succ);
    }
  }
  MBB.addSuccessor(NewMBB);

  if (TRI->trackLivenessAfterRegAlloc(MF)) {
    LivePhysRegs LiveRegs;
    computeAndAddLiveIns(LiveRegs, *NewMBB);
  }
}

bool AArch64GuardHighBitImpl::run(MachineFunction &MF) {
  std::optional<unsigned> Bit = getGuardBit(MF);
  if (!Bit)
    return false;

  const auto &Subtarget = MF.getSubtarget<AArch64Subtarget>();
  const AArch64InstrInfo *TII = Subtarget.getInstrInfo();
  const TargetRegisterInfo *TRI = Subtarget.getRegisterInfo();

  SmallVector<std::pair<MachineInstr *, Register>, 16> Targets;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      std::optional<Register> Reg = getGuardedTargetReg(MI);
      if (!Reg)
        continue;

      // Preserve R_AARCH64_[AUTH_]TLSDESC_CALL adjacency if emitted explicitly.
      if (MI.getIterator() != MBB.begin()) {
        auto Prev = std::prev(MI.getIterator());
        unsigned PrevOpc = Prev->getOpcode();
        if (PrevOpc == AArch64::TLSDESCCALL ||
            PrevOpc == AArch64::TLSAUTHDESCCALL)
          continue;
        if (PrevOpc == AArch64::GUARD_HIGH_BIT_CHECK &&
            Prev->getOperand(0).getReg() == *Reg &&
            Prev->getOperand(1).getImm() == static_cast<int64_t>(*Bit))
          continue;
      }

      Targets.emplace_back(&MI, *Reg);
    }
  }

  if (Targets.empty())
    return false;

  for (auto [MI, Reg] : Targets) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineBasicBlock::iterator InsertPt = MI->getIterator();

    // MachineVerifier requires all non-terminators to precede the first
    // terminator in an MBB, and BranchRelaxation requires conditional branches
    // to remain analyzable. If a conditional branch precedes this indirect
    // terminator in the same MBB, split a fallthrough block right before MI so
    // GUARD_HIGH_BIT_CHECK sits cleanly before NewMBB's single terminator.
    if (MI->isTerminator() && InsertPt != MBB->getFirstTerminator()) {
      splitBeforeTerminator(MF, *MBB, InsertPt, TRI);
      MBB = MI->getParent();
      InsertPt = MI->getIterator();
    }

    BuildMI(*MBB, InsertPt, MI->getDebugLoc(),
            TII->get(AArch64::GUARD_HIGH_BIT_CHECK))
        .addUse(Reg)
        .addImm(*Bit);
  }

  return true;
}
