//
// Created by user on 2023/09/24.
//

#include "lib/BC/Resolver/ResolverBase.h"

namespace remill {
ResolverBase::ResolverBase(const Arch *arch) : arch(arch) {}

ResolverBase::FunctionMapper
ResolverBase::getInstructions(llvm::Module *target_mod, uint64_t stop) {
  FunctionMapper result;
  for (llvm::Function &function : target_mod->functions()) {
    const llvm::StringRef &name = function.getName();
    if (name.starts_with(SleighLifter::kInstructionFunctionPrefix)) {
      uint64_t target = std::strtol(
          name.data() + SleighLifter::kInstructionFunctionPrefix.length() + 1,
          nullptr, 16);
      if (target <= stop) {
        result[target] = &function;
      }
    }
  }
  return result;
}
}  // namespace remill
