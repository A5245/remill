//
// Created by user on 2023/09/24.
//

#ifndef REMILL_RESOLVERBASE_H
#define REMILL_RESOLVERBASE_H

#include <lib/Arch/Sleigh/ControlFlowStructuring.h>
#include <lib/BC/Resolver/RuntimeContext.h>
#include <remill/Arch/Arch.h>

#include <map>

namespace remill {
class ResolverBase {
 public:
  typedef std::function<llvm::Value *(const std::string &)> FuncGetRegister;

  virtual ~ResolverBase() = default;

  virtual bool
  resolvedInstruction(Instruction &inst,
                      const std::vector<sleigh::RemillPcodeOp> &ops,
                      const ghidra::Sleigh *engine) const = 0;

  virtual void
  resolveSuccessors(Instruction &inst, const vector<sleigh::RemillPcodeOp> &ops,
                    const ghidra::Sleigh *engine, llvm::IRBuilder<> &irBuilder,
                    llvm::Function *func,
                    const FuncGetRegister &getRegister) const = 0;

 protected:
  typedef std::map<llvm::Function *, RuntimeContext::RegisterInfoPtr>
      FunctionBoundary;
  typedef std::map<uint64_t, llvm::Function *> FunctionMapper;

  const Arch *arch;

  explicit ResolverBase(const Arch *arch);

  virtual std::pair<FunctionMapper, FunctionBoundary>
  findTaintedInstChain(const std::map<uint64_t, llvm::Function *> &instList,
                       const RuntimeContext *context,
                       const std::string &targetRegister) const = 0;

  virtual uint64_t
  findReadNotStackMemory(const FunctionMapper &instList,
                         const RuntimeContext *context) const = 0;

  virtual std::pair<std::string, std::string>
  findBaseRegisterAndOffsetRegister(llvm::Function *ldr) const = 0;

  static FunctionMapper getInstructions(llvm::Module *target_mod,
                                        uint64_t stop = -1U);
};
}  // namespace remill

#endif  //REMILL_RESOLVERBASE_H
