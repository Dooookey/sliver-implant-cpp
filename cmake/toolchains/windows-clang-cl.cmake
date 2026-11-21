# windows-clang-cl.cmake - clang-cl + lld-link against the MSVC toolchain.
#
# Requirements:
#   * LLVM installed (clang-cl, lld-link on PATH)
#   * run from a "x64 Native Tools" prompt, or provide INCLUDE/LIB via the
#     environment; clang-cl consumes the same MSVC headers/libraries.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

set(CMAKE_C_COMPILER   clang-cl)
set(CMAKE_CXX_COMPILER clang-cl)
set(CMAKE_LINKER       lld-link)
set(CMAKE_AR           llvm-lib)
set(CMAKE_RC_COMPILER  llvm-rc)

# Keep ABI identical to the MSVC preset so `dumpbin /exports` diffs stay empty.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
