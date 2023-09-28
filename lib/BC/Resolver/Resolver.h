//
// Created by user on 2023/09/24.
//

#ifndef REMILL_RESOLVER_H
#define REMILL_RESOLVER_H

#include <lib/Arch/Sleigh/ControlFlowStructuring.h>
#include <lib/BC/Resolver/ResolverBase.h>
#include <remill/Arch/Arch.h>

namespace remill {
class Resolver {
 public:
  explicit Resolver(const Arch *arch);

  ~Resolver();

  bool resolvedInstruction(Instruction &inst,
                           const std::vector<sleigh::RemillPcodeOp> &op,
                           const ghidra::Sleigh *engine) const;

  void
  resolveSuccessors(Instruction &inst, const vector<sleigh::RemillPcodeOp> &ops,
                    const ghidra::Sleigh *engine, llvm::IRBuilder<> &irBuilder,
                    llvm::Function *func,
                    const ResolverBase::FuncGetRegister &getRegister) const;

 private:
  std::unique_ptr<ResolverBase> impl;
};
}  // namespace remill

#endif  //REMILL_RESOLVER_H
