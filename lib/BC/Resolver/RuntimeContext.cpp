//
// Created by user on 2023/09/20.
//

#include "lib/BC/Resolver/RuntimeContext.h"

#include <glog/logging.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Operator.h>
#include <llvm/Passes/PassBuilder.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>

#include <deque>
#include <ranges>

namespace remill {

RuntimeContext::RuntimeContext(Arch *arch)
    : baseSp(arch->StackPointerRegisterName()),
      arch(arch) {
  addressMapper[0] = std::make_unique<Context>();
  addressMapper[0]->sp[this->baseSp] = 0;
}

void RuntimeContext::updateStackInfo(remill::Instruction &inst,
                                     llvm::Function *function) {
  auto info = resolveRegisterInfo(function);
  auto *context = getContext(inst.pc);

  if (inst.function.starts_with(arch->GetCallName())) {
    context->sp.erase(std::string(arch->GetReturnRegister()));
    return;
  }

  std::string currentSp;
  bool readSp = std::any_of(info->read.begin(), info->read.end(),
                            [&context, &currentSp](const auto &data) -> bool {
                              bool result = context->sp.find(data.first) !=
                                            context->sp.end();
                              if (result) {
                                currentSp = data.first;
                              }
                              return result;
                            });
  llvm::StoreInst *regStore = nullptr;
  bool writeSp = std::any_of(info->write.begin(), info->write.end(),
                             [&context, &regStore](const auto &data) -> bool {
                               bool result = context->sp.find(data.first) !=
                                             context->sp.end();
                               if (result) {
                                 regStore = data.second;
                               }
                               return result;
                             });
  if (!readSp && !writeSp) {
    return;
  }

  auto &sp = context->sp;
  if (readSp) {
    if (info->write.empty()) {
      int64_t spHeight = sp[currentSp];
      auto callList = findTargetCall(function, "__remill_write_memory");
      for (auto *each : callList) {
        auto *addressPtr = each->getArgOperand(1);
        if (!llvm::isa<llvm::BinaryOperator>(addressPtr)) {
          continue;
        }
        auto *binOp = llvm::dyn_cast<llvm::BinaryOperator>(addressPtr);
        auto *constantOp =
            llvm::dyn_cast<llvm::ConstantInt>(binOp->getOperand(1));
        if (constantOp == nullptr) {
          continue;
        }
        int64_t offset = 0;
        if (llvm::isa<llvm::AddOperator>(binOp)) {
          offset = constantOp->getSExtValue();
        } else if (llvm::isa<llvm::SubOperator>(binOp)) {
          offset = -constantOp->getSExtValue();
        }
        spHeight += offset;
        context->stack[spHeight] = function;
      }
    } else if (!writeSp &&
               findTargetCall(function, "__remill_read_memory").empty()) {
      auto [targetReg, store] = info->write[0];
      auto tainted = findTaintIRInstruction(
          llvm::dyn_cast<llvm::Instruction>(store->getValueOperand()));
      auto load = std::find_if(tainted.rbegin(), tainted.rend(),
                               [](const auto *data) -> bool {
                                 return llvm::isa<llvm::LoadInst>(data);
                               });
      auto *pointer = getPointerOperand(*load);
      std::unordered_map<llvm::Value *, int64_t> values;
      values[pointer] = sp[currentSp];
      sp[info->write[0].first] = evalStackPointer(tainted, values);
    }
  }
  if (writeSp) {
    auto tainted = findTaintIRInstruction(
        llvm::dyn_cast<llvm::Instruction>(regStore->getValueOperand()));

    auto load = std::find_if(tainted.rbegin(), tainted.rend(),
                             [](const auto *data) -> bool {
                               return llvm::isa<llvm::LoadInst>(data);
                             });
    if (load != tainted.rend()) {
      auto *pointer = getPointerOperand(*load);
      bool fromSp = sp.find(pointer->getName().str()) != sp.end();
      bool func = findTargetCall(function, "__remill_read_memory").empty();
      if (fromSp && func) {
        std::unordered_map<llvm::Value *, int64_t> values;
        values[pointer] = sp[currentSp];
        sp[currentSp] = evalStackPointer(tainted, values);
      } else {
        std::for_each(
            info->write.begin(), info->write.end(),
            [&sp](const auto &data) -> void { sp.erase(data.first); });
      }
    } else if (llvm::isa<llvm::ConstantInt>(regStore->getValueOperand())) {
      sp.erase(regStore->getPointerOperand()->getName().str());
    } else {
      std::string buff;
      llvm::raw_string_ostream stringOstream(buff);
      stringOstream << *function;
      LOG(FATAL) << "Unknown resolve " << buff;
    }
  }
}

void RuntimeContext::dumpContext(uint64_t src, uint64_t dst) {
  auto *srcContext = getContext(src);
  CHECK(srcContext != nullptr) << "0x" << std::hex << src << " not found";

  addressMapper[dst] = std::make_unique<Context>();
  auto *result = addressMapper[dst].get();

  std::for_each(
      srcContext->sp.begin(), srcContext->sp.end(),
      [&result](const auto &data) { result->sp[data.first] = data.second; });

  std::for_each(
      srcContext->stack.begin(), srcContext->stack.end(),
      [&result](const auto &data) { result->stack[data.first] = data.second; });
}

RuntimeContext::Context *RuntimeContext::getContext(uint64_t address) const {
  auto it = addressMapper.find(address);
  if (it != addressMapper.end()) {
    return it->second.get();
  }
  LOG(FATAL) << "Context at 0x" << std::hex << address << " is empty";
}

bool RuntimeContext::isStackRegister(uint64_t address,
                                     const std::string &name) const {
  auto it = addressMapper.find(address);
  if (it == addressMapper.end()) {
    return false;
  }
  return it->second->sp.find(name) != it->second->sp.end();
}


std::vector<llvm::Instruction *>
RuntimeContext::findTaintIRInstruction(llvm::Instruction *src) {
  if (src == nullptr) {
    return {};
  }
  std::vector<llvm::Instruction *> result;
  result.push_back(src);
  std::deque<llvm::Instruction *> wait;
  wait.push_back(src);
  while (!wait.empty()) {
    auto *tmp = wait.front();
    wait.pop_front();
    for (size_t i = 0; i < tmp->getNumOperands(); i++) {
      llvm::Value *operand = tmp->getOperand(i);
      if (auto *inst = llvm::dyn_cast<llvm::Instruction>(operand)) {
        wait.push_back(inst);
        result.push_back(inst);
      }
    }
  }
  return result;
}

std::vector<llvm::CallInst *>
RuntimeContext::findTargetCall(llvm::Function *function, const char *prefix) {
  std::vector<llvm::CallInst *> result;
  for (auto &block : *function) {
    for (auto &inst : block) {
      if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        if (call->getCalledFunction()->getName().starts_with(prefix)) {
          result.push_back(call);
        }
      }
    }
  }
  return result;
}

int64_t
RuntimeContext::evalStackPointer(const std::vector<llvm::Instruction *> &rInst,
                                 ValueMapper &values) {
  for (auto it : std::ranges::reverse_view(rInst)) {
    if (llvm::isa<llvm::GetElementPtrInst>(it)) {
      continue;
    }
    if (auto *load = llvm::dyn_cast<llvm::LoadInst>(it)) {
      values[load] = values[load->getPointerOperand()];
    } else if (auto *sub = llvm::dyn_cast<llvm::SubOperator>(it)) {
      auto operand = llvm::dyn_cast<llvm::ConstantInt>(sub->getOperand(1));
      if (operand != nullptr) {
        values[sub] = values[sub->getOperand(0)] - operand->getSExtValue();
      } else {
        LOG(ERROR) << "Found unresolved sp instruction";
        values[sub] = 0;
      }
    } else if (auto *add = llvm::dyn_cast<llvm::AddOperator>(it)) {
      auto operand = llvm::dyn_cast<llvm::ConstantInt>(add->getOperand(1));
      if (operand != nullptr) {
        values[add] = values[add->getOperand(0)] + operand->getSExtValue();
      } else {
        LOG(ERROR) << "Found unresolved sp instruction";
        values[add] = 0;
      }
    } else {
      std::string tmp;
      llvm::raw_string_ostream ostream(tmp);
      ostream << *it;
      LOG(FATAL) << "Unknown op " << tmp;
    }
  }
  return values[*rInst.begin()];
}

RuntimeContext::RegisterInfoPtr
RuntimeContext::resolveRegisterInfo(llvm::Function *function) {
  auto result = std::make_unique<RegisterInfo>();
  std::vector<llvm::GetElementPtrInst *> registerRef;
  {
    llvm::BasicBlock &entry = function->getEntryBlock();
    for (auto &inst : entry) {
      auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst);
      if (gep == nullptr || !gep->hasName()) {
        continue;
      }
      auto *structTy =
          llvm::dyn_cast<llvm::StructType>(gep->getSourceElementType());
      if (structTy == nullptr) {
        continue;
      }
      if (structTy->hasName()) {
        registerRef.push_back(gep);
      }
    }
  }
  for (auto *gep : registerRef) {
    for (auto *use : gep->users()) {
      if (auto *load = llvm::dyn_cast<llvm::LoadInst>(use)) {
        result->read.emplace_back(gep->getName().str(), load);
      } else if (auto *store = llvm::dyn_cast<llvm::StoreInst>(use)) {
        result->write.emplace_back(gep->getName().str(), store);
      }
    }
  }
  return result;
}

void RuntimeContext::optimizeFunc(llvm::Function *function) {
  llvm::ModuleAnalysisManager mam;
  llvm::FunctionAnalysisManager fam;
  llvm::LoopAnalysisManager lam;
  llvm::CGSCCAnalysisManager cam;

  llvm::PassBuilder pb;

  pb.registerModuleAnalyses(mam);
  pb.registerFunctionAnalyses(fam);
  pb.registerLoopAnalyses(lam);
  pb.registerCGSCCAnalyses(cam);
  pb.crossRegisterProxies(lam, fam, cam, mam);

  llvm::FunctionPassManager fpm = pb.buildFunctionSimplificationPipeline(
      llvm::OptimizationLevel::O1, llvm::ThinOrFullLTOPhase::None);
  fpm.run(*function, fam);

  mam.clear();
  fam.clear();
  lam.clear();
  cam.clear();
}
}  // namespace remill
