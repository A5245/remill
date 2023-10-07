//
// Created by user on 2023/09/20.
//

#ifndef REMILL_RUNTIMECONTEXT_H
#define REMILL_RUNTIMECONTEXT_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>

#include <map>
#include <string>
#include <unordered_map>


namespace remill {

class Arch;
class Instruction;

class RuntimeContext {
 public:
  class Context {
   public:
    std::unordered_map<std::string, int64_t> sp;
    // only for fixed stack memory definition
    std::unordered_map<int64_t, llvm::Function *> stack;

    Context() = default;

    ~Context() = default;
  };

  typedef struct {
    std::vector<std::pair<std::string, llvm::LoadInst *>> read;
    std::vector<std::pair<std::string, llvm::StoreInst *>> write;
  } RegisterInfo;
  typedef std::unique_ptr<RegisterInfo> RegisterInfoPtr;

  typedef std::unordered_map<llvm::Value *, int64_t> ValueMapper;

  explicit RuntimeContext(Arch *arch);

  ~RuntimeContext() = default;

  void updateStackInfo(remill::Instruction &inst, llvm::Function *function);

  void dumpContext(uint64_t src, uint64_t dst);

  [[nodiscard]] Context *getContext(uint64_t address) const;

  [[nodiscard]] bool isStackRegister(uint64_t address,
                                     const std::string &name) const;

  static void optimizeFunc(llvm::Function *function);

  static RegisterInfoPtr resolveRegisterInfo(llvm::Function *function);

  static std::vector<llvm::CallInst *> findTargetCall(llvm::Function *function,
                                                      const char *prefix);
  static std::vector<llvm::Instruction *>
  findTaintIRInstruction(llvm::Instruction *src);

  static int64_t evalStackPointer(const std::vector<llvm::Instruction *> &rInst,
                                  ValueMapper &values);

 private:
  std::map<uint64_t, std::unique_ptr<Context>> addressMapper;
  std::string baseSp;
  Arch *arch;
};
}  // namespace remill

#endif  //REMILL_RUNTIMECONTEXT_H
