
#include <cstdint>
#include <cstddef>

int fuzzme_nofeedback(const uint8_t *data, size_t size) {
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return fuzzme_nofeedback(data, size);
}
