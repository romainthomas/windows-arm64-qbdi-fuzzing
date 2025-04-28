#include <cstddef>
#include <array>
#include <cstdint>

extern "C" void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2);
extern "C" void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2);
extern "C" void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop);

static std::array<uint8_t, 10> BITMAP;

class InitBitMap {
  public:
  InitBitMap() {
    BITMAP.fill(0);
    __sanitizer_cov_8bit_counters_init(BITMAP.data(), BITMAP.data() + BITMAP.size() - 1);
  }
};

static InitBitMap _;

int fuzzme_cov(const uint8_t *data, size_t size) {
  __sanitizer_cov_trace_const_cmp8(size, 0);
  __sanitizer_cov_trace_const_cmp4(data[0], 'Q');
  if (size > 0 && data[0] == 'Q') {
    __sanitizer_cov_trace_const_cmp8(size, 1);
    __sanitizer_cov_trace_const_cmp4(data[1], 'B');
    if (size > 1 && data[1] == 'B') {
      __sanitizer_cov_trace_const_cmp8(size, 2);
      __sanitizer_cov_trace_const_cmp4(data[2], 'D');
      if (size > 2 && data[2] == 'D') {
        __sanitizer_cov_trace_const_cmp8(size, 3);
        __sanitizer_cov_trace_const_cmp4(data[3], 'I');
        if (size > 3 && data[3] == 'I') {
          __sanitizer_cov_trace_const_cmp8(size, 4);
          __sanitizer_cov_trace_const_cmp4(data[4], '!');
          if (size > 4 && data[4] == '!') {
            __builtin_trap();
          } else { ++BITMAP[4]; }
        } else { ++BITMAP[3]; }
      } else { ++BITMAP[2]; }
    } else { ++BITMAP[1]; }
  } else { ++BITMAP[0]; }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return fuzzme_cov(data, size);
}
