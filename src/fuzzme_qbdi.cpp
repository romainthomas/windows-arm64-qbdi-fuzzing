#include <cstdio>
#include <array>
#include <cstdint>
#include <QBDI.h>
#include <llvm/ADT/DenseMap.h>
#include <spdlog/fmt/fmt.h>
#include "llvm/lib/Target/AArch64/AArch64.h"

#include <fuzzer/FuzzerTracePC.h>
#include <fuzzer/FuzzerIO.h>
#include <fuzzer/FuzzerInternal.h>

extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop);

template <typename... Args>
inline void log(const char *fmt, const Args &... args) {
  std::string msg = fmt::format(fmt::runtime(fmt), args...);
  return fuzzer::Printf("%s\n", msg.c_str());
}


static std::vector<uint8_t> BITMAP;

class InitBitMap {
  public:
  InitBitMap() {
    BITMAP.resize(0x1000);
    __sanitizer_cov_8bit_counters_init(BITMAP.data(), BITMAP.data() + BITMAP.size() - 1);
  }
};

static InitBitMap _;

int fuzzme(const uint8_t *data, size_t size) {
  if (size > 0 && data[0] == 'Q') {
    if (size > 1 && data[1] == 'B') {
      if (size > 2 && data[2] == 'D') {
        if (size > 3 && data[3] == 'I') {
          if (size > 4 && data[4] == '!') {
            __builtin_trap();
          }
        }
      }
    }
  }
  return 0;
}

std::unique_ptr<QBDI::VM> get_dbi() {
  using namespace QBDI;
  auto dbi = std::make_unique<QBDI::VM>();
  dbi->addInstrumentedModuleFromAddr((uintptr_t)&fuzzme);

  dbi->addVMEventCB(VMEvent::BASIC_BLOCK_ENTRY,
    [] (VM* vm, const VMState* state, GPRState* gpr, FPRState* fpr, void* ctx) {
      static size_t counter = 0;
      static llvm::DenseMap<uintptr_t, size_t> BB_CNT;
      if (auto it = BB_CNT.find(state->basicBlockStart); it != BB_CNT.end()) {
        ++BITMAP[it->second];
      } else {
        log("QBDI: New BB: 0x{:016x}", state->basicBlockStart);
        size_t idx = ++counter % BITMAP.size();
        BB_CNT.insert({state->basicBlockStart, idx});
        ++BITMAP[idx];
      }
      return VMAction::CONTINUE;
    }, nullptr);

  // Add callback on instructions: `cmp w[0-30], #ct`
  dbi->addOpcodeCB(llvm::AArch64::SUBSWri, InstPosition::PREINST,
    [] (VM* vm, GPRState* gpr, FPRState*, void*) {
      const llvm::MCInst* inst = vm->getOriginalMCInst();
      const size_t regw_idx = inst->getOperand(1).getReg() - llvm::AArch64::W0;
      const uintptr_t cst = inst->getOperand(2).getImm();
      const auto* gpr_ptr = reinterpret_cast<const uintptr_t*>(gpr);
      fuzzer::TPC.HandleCmp<uint32_t>(gpr->pc, (uint32_t)cst, (uint32_t)gpr_ptr[regw_idx]);
      return VMAction::CONTINUE;
    }, /*data=*/nullptr);

  // Add callback on instructions: `cmp x[0-30], #ct`
  dbi->addOpcodeCB(llvm::AArch64::SUBSXri, InstPosition::PREINST,
    [] (VM* vm, GPRState* gpr, FPRState*, void*) {
      const llvm::MCInst* inst = vm->getOriginalMCInst();
      const size_t regw_idx = inst->getOperand(1).getReg() - llvm::AArch64::X0;
      const uintptr_t cst = inst->getOperand(2).getImm();
      const auto* gpr_ptr = reinterpret_cast<const uintptr_t*>(gpr);
      fuzzer::TPC.HandleCmp<uint64_t>(gpr->pc, (uintptr_t)cst, (uintptr_t)gpr_ptr[regw_idx]);
      return VMAction::CONTINUE;
    }, /*data=*/nullptr);

  dbi->addOpcodeCB(llvm::AArch64::BRK, InstPosition::PREINST,
    [] (VM* vm, GPRState* gpr, FPRState*, void*) {
      log("QBDI: Booooooom!");
      fuzzer::Fuzzer::StaticCrashSignalCallback();
      return VMAction::STOP;
    }, /*data=*/nullptr);
  return dbi;
}

int fuzzme_qbdi(const uint8_t *data, size_t size) {
  using namespace QBDI;
  static auto DBI = get_dbi();
  GPRState* gpr = DBI->getGPRState();

  std::array<uint8_t, 0x1000> stack = {};
  auto bp = reinterpret_cast<uintptr_t>(stack.data());
  uintptr_t sp = bp + stack.size();

  gpr->pc = reinterpret_cast<uintptr_t>(fuzzme);
  gpr->x29 = bp;
  gpr->sp = sp;
  gpr->lr = 0xdeadc0de;
  gpr->x0 = reinterpret_cast<uintptr_t>(data);
  gpr->x1 = reinterpret_cast<uintptr_t>(size);

  DBI->run(gpr->pc, gpr->lr);

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return fuzzme_qbdi(data, size);
}
