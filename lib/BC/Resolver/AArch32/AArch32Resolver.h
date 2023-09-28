//
// Created by user on 2023/09/24.
//

#ifndef REMILL_AARCH32RESOLVER_H
#define REMILL_AARCH32RESOLVER_H

#include <lib/BC/Resolver/ResolverBase.h>

namespace remill {
class AArch32Resolver : public ResolverBase {
 public:
  explicit AArch32Resolver(const Arch *arch);

  ~AArch32Resolver() override = default;

  bool resolvedInstruction(Instruction &inst,
                           const std::vector<sleigh::RemillPcodeOp> &ops,
                           const Sleigh *engine) const override;

  void resolveSuccessors(Instruction &inst,
                         const vector<sleigh::RemillPcodeOp> &ops,
                         const ghidra::Sleigh *engine,
                         llvm::IRBuilder<> &irBuilder, llvm::Function *func,
                         const FuncGetRegister &getRegister) const override;

 protected:
  std::pair<FunctionMapper, FunctionBoundary>
  findTaintedInstChain(const map<uint64_t, llvm::Function *> &instList,
                       const RuntimeContext *context,
                       const string &targetRegister) const override;

  uint64_t findReadNotStackMemory(const FunctionMapper &instList,
                                  const RuntimeContext *context) const override;

  std::pair<std::string, std::string>
  findBaseRegisterAndOffsetRegister(llvm::Function *ldr) const override;

 private:
  [[nodiscard]] uint32_t readInt32(uint64_t address) const;

  bool evalCode(llvm::Function *functions,
                std::map<std::string, uint64_t> &values,
                const RuntimeContext::Context *runtimeContext,
                std::stringstream &error) const;

  uint64_t resolveArm32Table(const FunctionMapper &targetInst,
                             const FunctionBoundary &boundary,
                             const string &targetRegister,
                             const RuntimeContext *runtimeContext,
                             uint64_t before) const;

  std::unordered_map<uint32_t, uint64_t>
  resolveSuccess(uint64_t table, const RuntimeContext::Context *context,
                 llvm::Function *ldr) const;
};
}  // namespace remill

#endif  //REMILL_AARCH32RESOLVER_H
