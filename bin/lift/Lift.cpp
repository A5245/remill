/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FIRST
#  undef DEBUG
#  include <LIEF/ELF.hpp>
#endif

#include <capstone/capstone.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <remill/Version/Version.h>

#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>

DEFINE_string(os, REMILL_OS,
              "Operating system name of the code being "
              "translated. Valid OSes: linux, macos, windows, solaris.");
DEFINE_string(arch, REMILL_ARCH,
              "Architecture of the code being translated. "
              "Valid architectures: x86, amd64 (with or without "
              "`_avx` or `_avx512` appended), aarch64, aarch32");

DEFINE_uint64(address, 0,
              "Address at which we should assume the bytes are"
              "located in virtual memory.");

DEFINE_uint64(entry_address, 0,
              "Address of instruction that should be "
              "considered the entrypoint of this code. "
              "Defaults to the value of --address.");

DEFINE_string(bytes, "", "Hex-encoded byte string to lift.");

DEFINE_string(ir_out, "", "Path to file where the LLVM IR should be saved.");
DEFINE_string(bc_out, "",
              "Path to file where the LLVM bitcode should be "
              "saved.");

DEFINE_string(slice_inputs, "",
              "Comma-separated list of registers to treat as inputs.");
DEFINE_string(slice_outputs, "",
              "Comma-separated list of registers to treat as outputs.");

DEFINE_string(input, "", "input file to lift");

// Unhexlify the data passed to `--bytes`, and fill in `memory` with each
// such byte.
static remill::Arch::Memory UnhexlifyInputBytes(uint64_t addr_mask) {
  remill::Arch::Memory memory;

  for (size_t i = 0; i < FLAGS_bytes.size(); i += 2) {
    char nibbles[] = {FLAGS_bytes[i], FLAGS_bytes[i + 1], '\0'};
    char *parsed_to = nullptr;
    auto byte_val = strtol(nibbles, &parsed_to, 16);

    if (parsed_to != &(nibbles[2])) {
      std::cerr << "Invalid hex byte value '" << nibbles
                << "' specified in --bytes." << std::endl;
      exit(EXIT_FAILURE);
    }

    auto byte_addr = FLAGS_address + (i / 2);
    auto masked_addr = byte_addr & addr_mask;

    // Make sure that if a really big number is specified for `--address`,
    // that we don't accidentally wrap around and start filling out low
    // byte addresses.
    if (masked_addr < byte_addr) {
      std::cerr << "Too many bytes specified to --bytes, would result "
                << "in a 32-bit overflow.";
      exit(EXIT_FAILURE);

    } else if (masked_addr < FLAGS_address) {
      std::cerr << "Too many bytes specified to --bytes, would result "
                << "in a 64-bit overflow.";
      exit(EXIT_FAILURE);
    }

    memory[byte_addr] = static_cast<uint8_t>(byte_val);
  }

  return memory;
}

class AutoFree {
 private:
  cs_insn *inst;
  size_t size;

 public:
  explicit AutoFree() : inst(nullptr), size(0) {}

  size_t disassemble(csh handle, const uint8_t *code, size_t code_size,
                     uint64_t address, size_t count) {
    size = cs_disasm(handle, code, code_size, address, count, &inst);
    return size;
  }

  cs_insn &operator[](size_t index) const {
    return inst[index];
  }

  ~AutoFree() {
    if (inst != nullptr) {
      cs_free(inst, size);
    }
  }
};

static std::unordered_map<uint64_t, uint64_t>
resolveArm32PltFunction(LIEF::ELF::Binary *binary) {
  uint64_t vBase = 0;
  uint64_t size = 0;
  for (auto &dyn : binary->dynamic_entries()) {
    if (dyn.tag() == LIEF::ELF::DynamicEntry::TAG::JMPREL) {
      vBase = dyn.value();
    } else if (dyn.tag() == LIEF::ELF::DynamicEntry::TAG::PLTRELSZ) {
      size = dyn.value();
    }
  }
  vBase += size + 0x14;
  csh handle = 0;
  if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK) {
    return {};
  }
  if (cs_option(handle, CS_OPT_DETAIL, true) != CS_ERR_OK) {
    cs_close(&handle);
    return {};
  }
  auto data = binary->segment_from_offset(vBase)->content().data();
  uint64_t oBase = binary->virtual_address_to_offset(vBase).value();

  auto current = data + oBase;
  auto currentAddress = vBase;

  std::unordered_map<uint64_t, uint64_t> result;

  while (((uint32_t *) current)[0] != 0) {
    cs_insn *inst = nullptr;
    size_t instSize = cs_disasm(handle, current, 0xC, currentAddress, 3, &inst);
    cs_insn &adr = inst[0];
    cs_insn &add = inst[1];
    cs_insn &ldr = inst[2];

    uint64_t operand = add.detail->arm.op_count == 4
                           ? add.detail->arm.operands[2].imm
                                 << (32 - add.detail->arm.operands[3].imm)
                           : add.detail->arm.operands[2].imm;

    operand += ldr.address + ldr.detail->arm.operands[1].mem.disp;
    result[operand] = currentAddress;

    current += adr.size + add.size + ldr.size;
    currentAddress += adr.size + add.size + ldr.size;
    cs_free(inst, instSize);
  }

  cs_close(&handle);
  return result;
}

static std::vector<uint8_t> fallbackJunkCode(LIEF::ELF::Segment &segment) {
  auto data = segment.content();
  std::vector<uint8_t> result(data.size());
  memcpy(result.data(), data.data(), result.size());
  return result;
}

static std::vector<uint8_t> parseArm32JunkCode(LIEF::ELF::Segment &segment) {
  auto data = segment.content();
  std::vector<uint8_t> result(data.size());
  uint8_t *tmp = result.data();
  memcpy(tmp, data.data(), result.size());
  if ((segment.flags() & LIEF::ELF::Segment::FLAGS::X) ==
      LIEF::ELF::Segment::FLAGS::X) {
    csh handle;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) {
      return result;
    }
    if (cs_option(handle, CS_OPT_DETAIL, true) != CS_ERR_OK) {
      cs_close(&handle);
      return result;
    }
    for (size_t i = 0; i < result.size() - 4; i++) {
      // MOV ?, 0
      if ((*(uint32_t *) (tmp + i) & 0xFFFFFF) == 0x00F04F) {
        AutoFree cmpBlock;
        if (cmpBlock.disassemble(handle, tmp + i, 0x20, i, 3) != 3) {
          continue;
        }
        // MOV ?, 0
        // CMP ?, 0
        // BEQ next
        // junk data
        cs_insn &mov = cmpBlock[0];
        cs_insn &cmp = cmpBlock[1];
        cs_insn &beq = cmpBlock[2];
        if (mov.id != ARM_INS_MOV || cmp.id != ARM_INS_CMP ||
            strcmp(beq.mnemonic, "beq") != 0) {
          continue;
        }
        if (mov.detail->arm.operands[0].reg !=
            cmp.detail->arm.operands[0].reg) {
          continue;
        }

        uint64_t next = strtol(beq.op_str + 1, nullptr, 16);
        if (next - beq.address - beq.size > 8) {
          continue;
        }

        // next
        AutoFree jumpBlock;
        if (jumpBlock.disassemble(handle, (uint8_t *) tmp + next, 0x20, next,
                                  5) != 5) {
          continue;
        }
        cs_insn &subw = jumpBlock[0];
        cs_insn &add = jumpBlock[1];
        cs_insn &movConstant = jumpBlock[2];
        cs_insn &sub = jumpBlock[3];
        cs_insn &movPc = jumpBlock[4];
        if (strcmp(subw.mnemonic, "subw") != 0 || add.id != ARM_INS_ADD ||
            movConstant.id != ARM_INS_MOV || sub.id != ARM_INS_SUB ||
            movPc.id != ARM_INS_MOV ||
            movPc.detail->arm.operands[0].reg != ARM_REG_PC) {
          continue;
        }
        size_t nopSize = next - i + subw.size + add.size + movConstant.size +
                         sub.size + movPc.size;
        for (size_t index = 0; index < nopSize; index += 2) {
          // nop
          *(uint16_t *) (tmp + i + index) = 0xBF00;
        }
      }
    }
  }
  return result;
}
static std::unordered_map<uint64_t, uint64_t>
resolveArm64PltFunction(LIEF::ELF::Binary *binary) {
  // TODO arm64 plt function parse to got
  return {};
}

static std::vector<uint8_t> parseArm64JunkCode(LIEF::ELF::Segment &segment) {
  // TODO arm64 remove junk code
  return fallbackJunkCode(segment);
}

static remill::Arch::Memory
resolveSo(const char *path, remill::Arch *arch, std::vector<uint64_t> &noReturn,
          remill::TraceLifter::Symbols &symbols, std::set<uint64_t> &pltFunc) {
  remill::Arch::Memory memory;
  auto so = LIEF::ELF::Parser::parse(path);

  auto *parseJunkCode = arch->IsThumb() || arch->IsAArch32()
                            ? parseArm32JunkCode
                        : arch->IsAArch64() ? parseArm64JunkCode
                                            : fallbackJunkCode;

  for (auto &it : so->segments()) {
    if (it.type() == LIEF::ELF::Segment::TYPE::LOAD) {
      auto content = parseJunkCode(it);
      for (size_t i = 0; i < content.size(); i++) {
        memory[it.virtual_address() + i] = content[i];
      }
    }
  }

  for (auto &each : so->symbols()) {
    symbols[each.value()] = each.name();
  }

  if (!arch->IsThumb() && !arch->IsAArch32() && !arch->IsAArch64()) {
    return memory;
  }

  auto *func = arch->IsThumb() || arch->IsAArch32() ? resolveArm32PltFunction
                                                    : resolveArm64PltFunction;

  auto addressMapper = func(so.get());
  std::for_each(
      addressMapper.begin(), addressMapper.end(),
      [&pltFunc](const auto &each) -> void { pltFunc.insert(each.second); });

  for (auto &rel : so->pltgot_relocations()) {
    auto &name = rel.symbol()->name();
    uint64_t got = rel.address();
    auto it = addressMapper.find(got);
    if (it != addressMapper.end()) {
      if (name == "__stack_chk_fail" || name == "exit" ||
          name == "pthread_exit") {
        noReturn.push_back(it->second);
      }
      symbols[it->second] = name;
    }
  }
  return memory;
}

static void storeMemoryToModule(llvm::Module &module,
                                remill::Arch::Memory &memory) {
  llvm::LLVMContext &context = module.getContext();
  auto memStoreFuncType =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);

  auto memStoreFunc = llvm::Function::Create(
      memStoreFuncType, llvm::GlobalValue::LinkageTypes::ExternalLinkage,
      "memory_info", module);

  auto *u8PtrTy = llvm::Type::getInt8PtrTy(context);
  auto *u64Ty = llvm::Type::getInt64Ty(context);
  auto *structTy = llvm::StructType::get(context, {u64Ty, u8PtrTy});


  std::vector<llvm::Constant *> soData;
  auto addData = [&](uint64_t address, const std::vector<uint8_t> &data) {
    auto *store = llvm::ConstantDataArray::get(context, data);
    soData.push_back(llvm::ConstantStruct::get(
        structTy,
        {llvm::ConstantInt::get(u64Ty, address),
         new llvm::GlobalVariable(
             module, store->getType(), true,
             llvm::GlobalValue::LinkageTypes::PrivateLinkage, store)}));
  };

  std::vector<uint8_t> buff;
  uint64_t address = 0;
  for (; !memory.empty(); address++) {
    auto it = memory.find(address);
    if (it == memory.end()) {
      if (buff.empty()) {
        continue;
      }
      addData(address - buff.size(), buff);
      buff.clear();
    } else {
      buff.push_back(it->second);
      memory.erase(it);
    }
  }
  if (!buff.empty()) {
    addData(address - buff.size(), buff);
    buff.clear();
  }

  auto *entry = llvm::BasicBlock::Create(context, llvm::Twine::createNull(),
                                         memStoreFunc);
  llvm::IRBuilder<> builder(entry);

  auto *data = llvm::ConstantArray::get(
      llvm::ArrayType::get(structTy, soData.size()), soData);
  auto *memoryPtr = builder.CreateAlloca(data->getType(), nullptr, "memory");
  builder.CreateStore(data, memoryPtr);
  builder.CreateRetVoid();
}

// Looks for calls to a function like `__remill_function_return`, and
// replace its state pointer with a null pointer so that the state
// pointer never escapes.
static void MuteStateEscape(llvm::Module *module, const char *func_name) {
  auto func = module->getFunction(func_name);
  if (!func) {
    return;
  }

  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      auto arg_op = call_inst->getArgOperand(remill::kStatePointerArgNum);
      call_inst->setArgOperand(remill::kStatePointerArgNum,
                               llvm::UndefValue::get(arg_op->getType()));
    }
  }
}

static void SetVersion() {
  std::stringstream ss;
  auto vs = remill::version::GetVersionString();
  if (vs.empty()) {
    vs = "unknown";
  }
  ss << vs << "\n";
  if (!remill::version::HasVersionData()) {
    ss << "No extended version information found!\n";
  } else {
    ss << "Commit Hash: " << remill::version::GetCommitHash() << "\n";
    ss << "Commit Date: " << remill::version::GetCommitDate() << "\n";
    ss << "Last commit by: " << remill::version::GetAuthorName() << " ["
       << remill::version::GetAuthorEmail() << "]\n";
    ss << "Commit Subject: [" << remill::version::GetCommitSubject() << "]\n";
    ss << "\n";
    if (remill::version::HasUncommittedChanges()) {
      ss << "Uncommitted changes were present during build.\n";
    } else {
      ss << "All changes were committed prior to building.\n";
    }
  }
  google::SetVersionString(ss.str());
}

int main(int argc, char *argv[]) {
  SetVersion();
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  google::SetStderrLogging(google::GLOG_INFO);


  if (FLAGS_bytes.empty() && FLAGS_input.empty()) {
    std::cerr
        << "Please specify a sequence of hex bytes to --bytes or specify a path of lift file to --input."
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_input.empty() && FLAGS_bytes.size() % 2) {
    std::cerr << "Please specify an even number of nibbles to --bytes."
              << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_input.empty()) {
    std::cerr << "Please specify a path to --input." << std::endl;
    return EXIT_FAILURE;
  }

  if (!FLAGS_entry_address) {
    FLAGS_entry_address = FLAGS_address;
  }

  // Make sure `--address` and `--entry_address` are in-bounds for the target
  // architecture's address size.
  llvm::LLVMContext context;
  auto arch = remill::Arch::Get(context, FLAGS_os, FLAGS_arch);
  const uint64_t addr_mask = ~0ULL >> (64UL - arch->address_size);
  if (FLAGS_address != (FLAGS_address & addr_mask)) {
    std::cerr << "Value " << std::hex << FLAGS_address
              << " passed to --address does not fit into 32-bits. Did mean"
              << " to specify a 64-bit architecture to --arch?" << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_entry_address != (FLAGS_entry_address & addr_mask)) {
    std::cerr
        << "Value " << std::hex << FLAGS_entry_address
        << " passed to --entry_address does not fit into 32-bits. Did mean"
        << " to specify a 64-bit architecture to --arch?" << std::endl;
    return EXIT_FAILURE;
  }

  std::unique_ptr<llvm::Module> module(remill::LoadArchSemantics(arch.get()));

  const auto mem_ptr_type = arch->MemoryPointerType();

  std::vector<uint64_t> noReturn;
  remill::TraceLifter::Symbols symbols;
  std::set<uint64_t> pltFunc;
  remill::Arch::Memory memory = FLAGS_input.empty()
                                    ? UnhexlifyInputBytes(addr_mask)
                                    : resolveSo(FLAGS_input.c_str(), arch.get(),
                                                noReturn, symbols, pltFunc);
  arch->SetMemory(memory);
  remill::IntrinsicTable intrinsics(module.get());


  auto inst_lifter = arch->DefaultLifter(intrinsics);

  auto *trace = arch->GetTraceManager();
  remill::TraceLifter trace_lifter(arch.get(), trace, noReturn, symbols,
                                   pltFunc);

  // Lift all discoverable traces starting from `--entry_address` into
  // `module`.
  trace_lifter.Lift(FLAGS_entry_address);

  auto &traces = trace->traces;

  // Optimize the module, but with a particular focus on only the functions
  // that we actually lifted.
  remill::OptimizationGuide guide = {};
  remill::OptimizeModule(arch, module, traces, guide);

  // Create a new module in which we will move all the lifted functions. Prepare
  // the module for code of this architecture, i.e. set the data layout, triple,
  // etc.
  llvm::Module dest_module("lifted_code", context);
  arch->PrepareModuleDataLayout(&dest_module);

  llvm::Function *entry_trace = nullptr;
  const auto make_slice =
      !FLAGS_slice_inputs.empty() || !FLAGS_slice_outputs.empty();

  // Move the lifted code into a new module. This module will be much smaller
  // because it won't be bogged down with all of the semantics definitions.
  // This is a good JITing strategy: optimize the lifted code in the semantics
  // module, move it to a new module, instrument it there, then JIT compile it.
  for (auto &lifted_entry : traces) {
    if (lifted_entry.first == FLAGS_entry_address) {
      entry_trace = lifted_entry.second;
    }
    remill::MoveFunctionIntoModule(lifted_entry.second, &dest_module);

    // If we are providing a prototype, then we'll be re-optimizing the new
    // module, and we want everything to get inlined.
    if (make_slice) {
      lifted_entry.second->setLinkage(llvm::GlobalValue::InternalLinkage);
      lifted_entry.second->removeFnAttr(llvm::Attribute::NoInline);
      lifted_entry.second->addFnAttr(llvm::Attribute::InlineHint);
      lifted_entry.second->addFnAttr(llvm::Attribute::AlwaysInline);
    }
  }

  storeMemoryToModule(dest_module, memory);

  // We have a prototype, so go create a function that will call our entrypoint.
  if (make_slice) {
    CHECK_NOTNULL(entry_trace);

    llvm::SmallVector<llvm::StringRef, 4> input_reg_names;
    llvm::SmallVector<llvm::StringRef, 4> output_reg_names;
    llvm::StringRef(FLAGS_slice_inputs)
        .split(input_reg_names, ',', -1, false /* KeepEmpty */);
    llvm::StringRef(FLAGS_slice_outputs)
        .split(output_reg_names, ',', -1, false /* KeepEmpty */);

    CHECK(!(input_reg_names.empty() && output_reg_names.empty()))
        << "Empty lists passed to both --slice_inputs and --slice_outputs";

    // Use the registers to build a function prototype.
    llvm::SmallVector<llvm::Type *, 8> arg_types;
    arg_types.push_back(mem_ptr_type);

    for (auto &reg_name : input_reg_names) {
      const auto reg = arch->RegisterByName(reg_name.str());
      CHECK(reg != nullptr)
          << "Invalid register name '" << reg_name.str()
          << "' used in input slice list '" << FLAGS_slice_inputs << "'";

      arg_types.push_back(reg->type);
    }

    const auto first_output_reg_index = arg_types.size();

    // Outputs are "returned" by pointer through arguments.
    for (auto &reg_name : output_reg_names) {
      const auto reg = arch->RegisterByName(reg_name.str());
      CHECK(reg != nullptr)
          << "Invalid register name '" << reg_name.str()
          << "' used in output slice list '" << FLAGS_slice_outputs << "'";

      arg_types.push_back(llvm::PointerType::get(context, 0));
    }

    const auto state_type = arch->StateStructType();
    const auto func_type =
        llvm::FunctionType::get(mem_ptr_type, arg_types, false);
    const auto func = llvm::Function::Create(
        func_type, llvm::GlobalValue::ExternalLinkage, "slice", &dest_module);

    // Store all of the function arguments (corresponding with specific registers)
    // into the stack-allocated `State` structure.
    auto entry = llvm::BasicBlock::Create(context, "", func);
    llvm::IRBuilder<> ir(entry);

    const auto state_ptr = ir.CreateAlloca(state_type);

    const remill::Register *pc_reg =
        arch->RegisterByName(arch->ProgramCounterRegisterName());

    CHECK(pc_reg != nullptr)
        << "Could not find the register in the state structure "
        << "associated with the program counter.";

    // Store the program counter into the state.
    const auto pc_reg_ptr = pc_reg->AddressOf(state_ptr, entry);
    const auto trace_pc =
        llvm::ConstantInt::get(pc_reg->type, FLAGS_entry_address, false);
    ir.SetInsertPoint(entry);
    ir.CreateStore(trace_pc, pc_reg_ptr);

    auto args_it = func->arg_begin();
    for (auto &reg_name : input_reg_names) {
      const auto reg = arch->RegisterByName(reg_name.str());
      auto &arg = *++args_it;  // Pre-increment, as first arg is memory pointer.
      arg.setName(reg_name);
      CHECK_EQ(arg.getType(), reg->type);
      auto reg_ptr = reg->AddressOf(state_ptr, entry);
      ir.SetInsertPoint(entry);
      ir.CreateStore(&arg, reg_ptr);
    }

    llvm::Value *mem_ptr = &*func->arg_begin();

    llvm::Value *trace_args[remill::kNumBlockArgs] = {};
    trace_args[remill::kStatePointerArgNum] = state_ptr;
    trace_args[remill::kMemoryPointerArgNum] = mem_ptr;
    trace_args[remill::kPCArgNum] = llvm::ConstantInt::get(
        llvm::IntegerType::get(context, arch->address_size),
        FLAGS_entry_address, false);

    mem_ptr = ir.CreateCall(entry_trace, trace_args);

    // Go read all output registers out of the state and store them
    // into the output parameters.
    args_it = func->arg_begin();
    for (size_t i = 0, j = 0; i < func->arg_size(); ++i, ++args_it) {
      if (i < first_output_reg_index) {
        continue;
      }

      const auto &reg_name = output_reg_names[j++];
      const auto reg = arch->RegisterByName(reg_name.str());
      auto &arg = *args_it;
      arg.setName(reg_name + "_output");

      auto reg_ptr = reg->AddressOf(state_ptr, entry);
      ir.SetInsertPoint(entry);
      ir.CreateStore(ir.CreateLoad(reg->type, reg_ptr), &arg);
    }

    // Return the memory pointer, so that all memory accesses are
    // preserved.
    ir.CreateRet(mem_ptr);

    // We want the stack-allocated `State` to be subject to scalarization
    // and mem2reg, but to "encourage" that, we need to prevent the
    // `alloca`d `State` from escaping.
    MuteStateEscape(&dest_module, "__remill_error");
    MuteStateEscape(&dest_module, "__remill_function_call");
    MuteStateEscape(&dest_module, "__remill_function_return");
    MuteStateEscape(&dest_module, "__remill_jump");
    MuteStateEscape(&dest_module, "__remill_missing_block");

    guide.slp_vectorize = true;
    guide.loop_vectorize = true;

    CHECK(remill::VerifyModule(&dest_module));
    remill::OptimizeBareModule(&dest_module, guide);
  }

  int ret = EXIT_SUCCESS;

  if (!FLAGS_ir_out.empty()) {
    if (!remill::StoreModuleIRToFile(&dest_module, FLAGS_ir_out, true)) {
      LOG(ERROR) << "Could not save LLVM IR to " << FLAGS_ir_out;
      ret = EXIT_FAILURE;
    }
  }
  if (!FLAGS_bc_out.empty()) {
    if (!remill::StoreModuleToFile(&dest_module, FLAGS_bc_out, true)) {
      LOG(ERROR) << "Could not save LLVM bitcode to " << FLAGS_bc_out;
      ret = EXIT_FAILURE;
    }
  }

  return ret;
}
