//
// Created by user on 2023/09/24.
//

#include "lib/BC/Resolver/Resolver.h"

#include <lib/BC/Resolver/AArch32/AArch32Resolver.h>

namespace remill {
Resolver::Resolver(const Arch *arch) {
  if (arch->IsAArch32() || arch->IsThumb()) {
    impl = std::make_unique<AArch32Resolver>(arch);
  } else {
    impl = nullptr;
  }
}

Resolver::~Resolver() = default;

bool Resolver::resolvedInstruction(Instruction &inst,
                                   const vector<sleigh::RemillPcodeOp> &op,
                                   const ghidra::Sleigh *engine) const {
  if (impl == nullptr) {
    return false;
  }
  return impl->resolvedInstruction(inst, op, engine);
}

void Resolver::resolveSuccessors(
    Instruction &inst, const vector<sleigh::RemillPcodeOp> &ops,
    const ghidra::Sleigh *engine, llvm::IRBuilder<> &irBuilder,
    llvm::Function *func,
    const ResolverBase::FuncGetRegister &getRegister) const {
  impl->resolveSuccessors(inst, ops, engine, irBuilder, func, getRegister);
}

}  // namespace remill