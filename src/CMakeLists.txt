cmake_minimum_required(VERSION 3.24)
project(dbi-fuzzing LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(QBDI REQUIRED)
find_package(spdlog REQUIRED)
find_package(LLVM REQUIRED)

message(STATUS "LLVM STATUS:
  Definitions ${LLVM_DEFINITIONS}
  Includes    ${LLVM_INCLUDE_DIRS}
  Libraries   ${LLVM_LIBRARY_DIRS}
  Targets     ${LLVM_TARGETS_TO_BUILD}
  RTTI        ${LLVM_ENABLE_RTTI}"
)

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

llvm_map_components_to_libnames(LLVM_LIBS
  core
  mc
  AllTargetsCodeGens
  AllTargetsAsmParsers
  AllTargetsDescs
  AllTargetsDisassemblers
  AllTargetsInfos
  AllTargetsMCAs
)
# ============================================================================
# Fuzzme without feedback
# ============================================================================
add_executable(fuzzme-nofeedback ./fuzzme_nofeedback.cpp)
target_compile_options(fuzzme-nofeedback PRIVATE -O3 -g)
target_link_options(fuzzme-nofeedback PRIVATE -fsanitize=fuzzer)

# ============================================================================
# Fuzzme with QBDI feedback
# ============================================================================
add_executable(fuzzme-qbdi ./fuzzme_qbdi.cpp)
target_link_libraries(fuzzme-qbdi ${LLVM_LIBS})
target_link_libraries(fuzzme-qbdi QBDI::QBDI spdlog::spdlog)
target_compile_options(fuzzme-qbdi PRIVATE -O3 -g)
target_link_options(fuzzme-qbdi PRIVATE -fsanitize=fuzzer)

target_include_directories(fuzzme-qbdi PRIVATE
  /llvm-cross-compile/lib/clang/20/include
  /llvm-cross-compile/lib/clang/20/include/fuzzer/
)

# ============================================================================
# Fuzzme with manual source code instrumentation
# ============================================================================
add_executable(fuzzme-cov ./fuzzme_cov.cpp)
target_link_libraries(fuzzme-cov ${LLVM_LIBS})
target_link_libraries(fuzzme-cov spdlog::spdlog)
target_compile_options(fuzzme-cov PRIVATE -O3 -g)
target_link_options(fuzzme-cov PRIVATE -fsanitize=fuzzer)

target_include_directories(fuzzme-cov PRIVATE
  /llvm-cross-compile/lib/clang/20/include
  /llvm-cross-compile/lib/clang/20/include/fuzzer/
)
