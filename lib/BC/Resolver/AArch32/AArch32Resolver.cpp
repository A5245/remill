//
// Created by user on 2023/09/24.
//

#include "AArch32Resolver.h"

#include <llvm/IR/PatternMatch.h>
#include <remill/BC/Util.h>

#include <ranges>

namespace remill {

AArch32Resolver::AArch32Resolver(const Arch *arch) : ResolverBase(arch) {}

uint32_t AArch32Resolver::readInt32(uint64_t address) const {
  auto *manager = arch->GetTraceManager();
  uint32_t value = 0;
  auto *tmp = (uint8_t *) &value;
  for (size_t i = 0; i < sizeof(uint32_t); i++) {
    if (!manager->TryReadExecutableByte(address + i, tmp + i)) {
      return -1U;
    }
  }
  return value;
}

bool AArch32Resolver::evalCode(llvm::Function *functions,
                               map<std::string, uint64_t> &values,
                               const RuntimeContext::Context *runtimeContext,
                               std::stringstream &error) const {
  std::deque<llvm::BasicBlock *> worklist;
  worklist.push_back(&functions->getEntryBlock());
  while (!worklist.empty()) {
    llvm::BasicBlock *block = worklist.front();
    worklist.pop_front();

    for (llvm::Instruction &inst : *block) {
      if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
        if (auto *structTy =
                llvm::dyn_cast<llvm::StructType>(gep->getSourceElementType())) {
          CHECK(structTy->getName() == "struct.State")
              << "Found unknown struct type at: "
              << functions->getName().data();
        }
      } else if (auto *alloc = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
        CHECK(alloc->hasName());
      } else if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
        llvm::Value *src = store->getValueOperand();
        llvm::Value *dst = store->getPointerOperand();
        if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(src)) {
          values[dst->getName().str()] = constant->getZExtValue();
        } else {
          if (dst->getName() == "MEMORY") {
            continue;
          }
          auto value = values.find(std::to_string((uintptr_t) src));
          CHECK(value != values.end());
          values[dst->getName().str()] = value->second;
        }
      } else if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
        llvm::StringRef name = load->getPointerOperand()->getName();
        if (name == "MEMORY") {
          continue;
        }
        auto value = values.find(name.str());
        if (value == values.end()) {
          auto stack = runtimeContext->sp.find(name.str());
          if (stack != runtimeContext->sp.end()) {
            values[std::to_string((uintptr_t) load)] = stack->second;
            continue;
          }
          error << "Value " << name.str() << " not found";
          return false;
        }
        values[std::to_string((uintptr_t) load)] = value->second;
      } else if (auto *zExt = llvm::dyn_cast<llvm::ZExtInst>(&inst)) {
        auto value =
            values.find(std::to_string((uintptr_t) zExt->getOperand(0)));
        CHECK(value != values.end());
        values[std::to_string((uintptr_t) zExt)] = value->second;
      } else if (auto *binOp = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {
        llvm::Value *left = binOp->getOperand(0);
        llvm::Value *right = binOp->getOperand(1);
        uint64_t leftConst;
        if (auto *leftConstant = llvm::dyn_cast<llvm::ConstantInt>(left)) {
          leftConst = leftConstant->getZExtValue();
        } else {
          auto it = values.find(std::to_string((uintptr_t) left));
          CHECK(it != values.end());
          leftConst = it->second;
        }
        uint64_t rightConst;
        if (auto *rightConstant = llvm::dyn_cast<llvm::ConstantInt>(right)) {
          rightConst = rightConstant->getZExtValue();
        } else {
          auto it = values.find(std::to_string((uintptr_t) right));
          CHECK(it != values.end());
          rightConst = it->second;
        }
        std::optional<uint64_t> result;
        switch (binOp->getOpcode()) {
          case llvm::BinaryOperator::Add:
            result = leftConst + rightConst;
            break;
          case llvm::BinaryOperator::Sub:
            result = leftConst - rightConst;
            break;
          case llvm::BinaryOperator::Mul:
            result = leftConst * rightConst;
            break;
          case llvm::BinaryOperator::And:
            result = leftConst & rightConst;
            break;
          case llvm::BinaryOperator::Or: result = leftConst | rightConst; break;
          default: break;
        }
        CHECK(result.has_value());
        values[std::to_string((uintptr_t) binOp)] = result.value();
      } else if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        auto name = call->getCalledFunction()->getName();
        if (name == "__remill_read_memory_32") {
          auto it =
              values.find(std::to_string((uintptr_t) call->getArgOperand(1)));
          if (it == values.end()) {
            error << "Memory ptr not define";
            return false;
          }
          uint32_t address = readInt32(it->second);
          if (address == -1U) {
            address = values[std::to_string(it->second)];
          }
          values[std::to_string((uintptr_t) call)] = address;
        } else if (name == "__remill_write_memory_32") {
          uint64_t value =
              values[std::to_string((uintptr_t) call->getArgOperand(2))];
          uint64_t address =
              values[std::to_string((uintptr_t) call->getArgOperand(1))];
          values[std::to_string(address)] = value;
        } else {
          llvm::outs() << *functions << '\n';
          LOG(FATAL) << "Not impl " << name.data();
        }
      } else if (auto *br = llvm::dyn_cast<llvm::BranchInst>(&inst)) {
        CHECK(br->isUnconditional());
        worklist.push_back(br->getSuccessor(0));
      } else if (llvm::isa<llvm::ReturnInst>(&inst)) {
        worklist.clear();
        break;
      }
    }
  }
  return true;
}

uint64_t AArch32Resolver::resolveArm32Table(
    const ResolverBase::FunctionMapper &targetInst,
    const ResolverBase::FunctionBoundary &boundary,
    const string &targetRegister, const RuntimeContext *runtimeContext,
    uint64_t before) const {
  std::map<std::string, uint64_t> context;
  for (auto &it : targetInst) {
    if (it.first >= before) {
      break;
    }
    llvm::Function *currentInst = it.second;
    auto *info = boundary.find(currentInst)->second.get();

    if (std::find_if(info->read.begin(), info->read.end(),
                     [](const auto &data) -> bool {
                       return data.first == "PC";
                     }) != info->read.end()) {
      const char *tmpStr = currentInst->getName().data() +
                           SleighLifter::kInstructionFunctionPrefix.length() +
                           1;
      uint64_t pc = std::strtol(tmpStr, nullptr, 16) + 4;

      context["PC"] = pc;
    }
    std::stringstream ss;
    if (!evalCode(currentInst, context, runtimeContext->getContext(it.first),
                  ss)) {
      ss << " at 0x" << std::hex << it.first;
      LOG(FATAL) << ss.str();
    }
  }
  auto targetValue = context.find(targetRegister);
  CHECK(targetValue != context.end());
  return targetValue->second;
}

std::pair<ResolverBase::FunctionMapper, ResolverBase::FunctionBoundary>
AArch32Resolver::findTaintedInstChain(
    const map<uint64_t, llvm::Function *> &instList,
    const RuntimeContext *context, const string &targetRegister) const {
  std::set<std::string> traceWriteRegister;
  traceWriteRegister.insert(targetRegister);

  auto parseMem =
      [&context, this](
          uint64_t address, const llvm::Function *func,
          const std::vector<llvm::CallInst *> &callMem,
          const std::function<void(const std::string &)> &callbackReg,
          const std::function<void(llvm::LoadInst *,
                                   const std::vector<llvm::Instruction *> &)>
              &callbackStack) -> void {
    for (auto *each : callMem) {
      auto *binOp = llvm::dyn_cast<llvm::Instruction>(each->getArgOperand(1));
      auto list = RuntimeContext::findTaintIRInstruction(binOp);

      auto view = std::ranges::reverse_view(list);
      for (auto *inst : view) {
        if (auto *load = llvm::dyn_cast<llvm::LoadInst>(inst)) {
          auto tmp =
              findBaseRegisterAndOffsetRegister(each->getParent()->getParent());
          auto loadBase = tmp.first;
          if (context->isStackRegister(address, loadBase)) {
            callbackStack(load, list);
          } else {
            callbackReg(loadBase);
          }
        }
      }
    }
  };

  std::set<int64_t> traceStack;

  FunctionMapper targetInst;
  FunctionBoundary boundary;
  for (auto it = instList.rbegin(); it != instList.rend(); it++) {
    if (traceWriteRegister.empty() && traceStack.empty()) {
      break;
    }
    auto regInfo = RuntimeContext::resolveRegisterInfo(it->second);
    bool matchWrite = std::any_of(
        traceWriteRegister.begin(), traceWriteRegister.end(),
        [&regInfo](const auto &name) -> bool {
          return std::find_if(regInfo->write.begin(), regInfo->write.end(),
                              [&name](const auto &data) -> bool {
                                return data.first == name;
                              }) != regInfo->write.end();
        });

    auto readMem =
        RuntimeContext::findTargetCall(it->second, "__remill_read_memory");

    auto writeMem =
        RuntimeContext::findTargetCall(it->second, "__remill_write_memory");

    bool matchStackWrite =
        regInfo->write.empty() && !writeMem.empty() &&
        std::any_of(regInfo->read.begin(), regInfo->read.end(),
                    [&context, &it](const auto &data) -> bool {
                      return context->isStackRegister(it->first, data.first);
                    });

    // LDR R1, [R2,R3,LSL#2] expect R3
    if (!readMem.empty() && !matchStackWrite) {
      auto [base, offset] = findBaseRegisterAndOffsetRegister(it->second);
      if (!offset.empty()) {
        std::erase_if(regInfo->read, [&offset](const auto &data) -> bool {
          return data.first == offset;
        });
      }
    }

    if (matchWrite) {

      std::for_each(
          regInfo->write.begin(), regInfo->write.end(),
          [&traceWriteRegister](
              const std::pair<std::string, llvm::StoreInst *> &data) -> void {
            traceWriteRegister.erase(data.first);
          });

      targetInst[it->first] = it->second;
      if (readMem.empty()) {
        std::for_each(regInfo->read.begin(), regInfo->read.end(),
                      [&traceWriteRegister](const auto &data) {
                        traceWriteRegister.insert(data.first);
                      });
      } else {
        RuntimeContext::Context *current = context->getContext(it->first);
        parseMem(
            it->first, it->second, readMem,
            [&traceWriteRegister](const auto &loadBase) {
              traceWriteRegister.insert(loadBase);
            },
            [&current, &traceStack, &context, &it](
                llvm::LoadInst *load,
                const std::vector<llvm::Instruction *> &list) {
              auto *loadPtr = load->getPointerOperand();
              int64_t value =
                  current->sp.find(loadPtr->getName().str())->second;
              RuntimeContext::ValueMapper mapper;
              mapper[loadPtr] = value;

              int64_t stackOffset =
                  RuntimeContext::evalStackPointer(list, mapper);

              auto stack = context->getContext(it->first)->stack;
              auto stackWrite = stack.find(stackOffset);
              CHECK(stackWrite != stack.end());

              // move curse to definition stack instruction
              {
                while (it->second != stackWrite->second) {
                  it++;
                }
                it--;
              }

              traceStack.insert(stackOffset);
            });
      }
      boundary[it->second] = std::move(regInfo);
    } else if (matchStackWrite) {
      RuntimeContext::Context *current = context->getContext(it->first);
      parseMem(
          it->first, it->second, writeMem, [](const auto &) {},
          [&current, &traceStack, &targetInst, &boundary, &it, &regInfo,
           &traceWriteRegister](llvm::LoadInst *load,
                                const std::vector<llvm::Instruction *> &list) {
            auto *loadPtr = load->getPointerOperand();
            auto name = loadPtr->getName().str();
            int64_t value = current->sp.find(name)->second;
            RuntimeContext::ValueMapper mapper;
            mapper[loadPtr] = value;
            int64_t offset = RuntimeContext::evalStackPointer(list, mapper);
            if (traceStack.find(offset) == traceStack.end()) {
              return;
            }
            targetInst[it->first] = it->second;
            std::for_each(regInfo->read.begin(), regInfo->read.end(),
                          [&traceWriteRegister, &name](const auto &each) {
                            if (each.first != name) {
                              traceWriteRegister.insert(each.first);
                            }
                          });
            boundary[it->second] = std::move(regInfo);
            traceStack.erase(offset);
          });
    }
    if (targetInst.size() == 10) {
      break;
    }
    traceWriteRegister.erase("PC");
  }

  return {std::move(targetInst), std::move(boundary)};
}

uint64_t AArch32Resolver::findReadNotStackMemory(
    const ResolverBase::FunctionMapper &instList,
    const RuntimeContext *context) const {

  for (const auto &it : std::ranges::reverse_view(instList)) {
    auto read =
        RuntimeContext::findTargetCall(it.second, "__remill_read_memory");
    if (read.empty()) {
      continue;
    }
    for (auto *call : read) {
      auto taintedIr = RuntimeContext::findTaintIRInstruction(
          llvm::dyn_cast<llvm::Instruction>(call->getArgOperand(1)));
      for (auto *inst : std::ranges::reverse_view(taintedIr)) {
        if (llvm::isa<llvm::LoadInst>(inst)) {
          llvm::Value *pointer = llvm::getPointerOperand(inst);
          if (!context->isStackRegister(it.first, pointer->getName().str())) {
            return it.first;
          }
        }
      }
    }
  }
  return -1U;
}

std::pair<std::string, std::string>
AArch32Resolver::findBaseRegisterAndOffsetRegister(llvm::Function *ldr) const {
  auto info = RuntimeContext::resolveRegisterInfo(ldr);
  using namespace llvm::PatternMatch;

  // LDR.W R0, [R1,R2,LSL#2]
  for (auto &block : *ldr) {
    for (auto &inst : block) {
      llvm::Value *table = nullptr;
      if (match(&inst, m_Shl(m_Load(m_Value(table)), m_Value()))) {
        std::string offset = table->getName().data();
        info->read.erase(std::find_if(info->read.begin(), info->read.end(),
                                      [&offset](const auto &data) -> bool {
                                        return data.first == offset;
                                      }));
        return {info->read[0].first, offset};
      }
    }
  }
  for (auto &block : *ldr) {
    for (auto &inst : block) {
      llvm::Value *base = nullptr;
      llvm::Value *offset = nullptr;
      if (match(&inst, m_Add(m_Load(m_Value(base)), m_Load(m_Value(offset))))) {
        return {base->getName().data(), offset->getName().data()};
      } else if (match(&inst, m_Add(m_Load(m_Value(base)), m_ConstantInt()))) {
        return {base->getName().data(), ""};
      }
    }
  }
  return {info->read[info->read.size() - 1].first, ""};
}

bool AArch32Resolver::resolvedInstruction(
    Instruction &inst, const std::vector<sleigh::RemillPcodeOp> &ops,
    const Sleigh *engine) const {
  std::string pcName = arch->ProgramCounterRegisterName().data();
  for (auto &each : pcName) {
    each = (char) tolower(each);
  }
  if (inst.function != "mov" || !inst.op_str.starts_with(pcName)) {
    return false;
  }
  return std::any_of(
      ops.rbegin(), ops.rend(), [&engine, &pcName](auto &op) -> bool {
        return op.op == OpCode::CPUI_BRANCHIND && op.vars.size() == 1 &&
               engine->getRegisterName(op.vars[0].space, op.vars[0].offset,
                                       op.vars[0].size) == pcName;
      });
}

void AArch32Resolver::resolveSuccessors(
    Instruction &inst, const vector<sleigh::RemillPcodeOp> &ops,
    const ghidra::Sleigh *engine, llvm::IRBuilder<> &irBuilder,
    llvm::Function *func, const FuncGetRegister &getRegister) const {
  std::string pcRegister = arch->ProgramCounterRegisterName().data();
  for (auto &each : pcRegister) {
    each = (char) tolower(each);
  }

  auto copy = std::find_if(
      ops.rbegin(), ops.rend(), [&engine, &pcRegister](auto &op) -> bool {
        if (op.op != OpCode::CPUI_COPY || !op.outvar.has_value()) {
          return false;
        }
        auto &out = op.outvar.value();
        return engine->getRegisterName(out.space, out.offset, out.size) ==
               pcRegister;
      });

  CHECK(copy != ops.rend())
      << "Source register not found at: 0x" << std::hex << inst.pc;

  auto &srcReg = copy->vars[0];
  std::string regName =
      engine->getRegisterName(srcReg.space, srcReg.offset, (int4) srcReg.size);
  for (char &each : regName) {
    each = (char) toupper(each);
  }
  llvm::Module *module = func->getParent();
  auto instList = getInstructions(module, inst.pc);

  auto *context = inst.context;

  auto [tmpInst, tmpBoundary] =
      findTaintedInstChain(instList, context, regName);

  auto ldrAddress = findReadNotStackMemory(tmpInst, context);

  CHECK(ldrAddress != -1U) << "Non-read stack memory not found at: 0x"
                           << std::hex << inst.pc;

  auto [baseRegister, offsetRegister] =
      findBaseRegisterAndOffsetRegister(tmpInst[ldrAddress]);

  uint64_t table = resolveArm32Table(tmpInst, tmpBoundary, baseRegister,
                                     context, ldrAddress);

  auto successors = resolveSuccess(table, context->getContext(ldrAddress),
                                   tmpInst.find(ldrAddress)->second);
  if (successors.size() == 1) {
    inst.branch_taken_pc = successors[0];
    inst.category = Instruction::kCategoryDirectJump;
  } else if (successors.size() == 2) {
    llvm::Value *offsetValue = getRegister(offsetRegister);

    irBuilder.CreateStore(
        irBuilder.CreateZExt(
            irBuilder.CreateICmpEQ(offsetValue, irBuilder.getInt32(1)),
            irBuilder.getInt8Ty()),
        func->getArg(2));
    inst.branch_not_taken_pc = successors[0];
    inst.branch_taken_pc = successors[1];
    inst.category = Instruction::kCategoryConditionalBranch;
  }
}

std::unordered_map<uint32_t, uint64_t>
AArch32Resolver::resolveSuccess(uint64_t table,
                                const RuntimeContext::Context *context,
                                llvm::Function *ldr) const {
  std::unordered_map<uint32_t, uint64_t> result;

  auto info = RuntimeContext::resolveRegisterInfo(ldr);
  if (info->read.size() == 1) {
    std::map<std::string, uint64_t> values;
    values[info->read[0].first] = table;
    std::stringstream ss;
    evalCode(ldr, values, context, ss);
    auto it = values.find(info->write[0].first);

    CHECK(it != values.end())
        << "Failed to find register: " << info->write[0].first;

    result[0] = it->second;
  } else if (info->read.size() == 2) {
    result[0] = readInt32(table);
    result[1] = readInt32(table + sizeof(uint32_t));
  }

  return result;
}
}  // namespace remill