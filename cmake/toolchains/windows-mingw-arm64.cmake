# windows-mingw-arm64.cmake - aarch64 cross compile from WSL/Linux.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   aarch64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER aarch64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER  aarch64-w64-mingw32-windres)

set(CMAKE_FIND_ROOT_PATH /usr/aarch64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_EXE_LINKER_FLAGS_INIT    "-static-libgcc -static-libstdc++")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-static-libgcc -static-libstdc++")
