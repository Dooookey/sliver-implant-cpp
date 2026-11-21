# implant-cpp

C/C++ re-implementation of the Sliver implant runtime. See `../docs/refactor/` for the
full plan (research, architecture, build system, milestones, risks).

**M0 scope (current):** toolchain matrix, build-time configuration injection, platform
abstraction skeleton, config self-test. Session/beacon loops, transports and crypto land
in M1+.

## Layout

```
implant-cpp/
├── CMakeLists.txt          top level (options → config generation → core lib → artifact)
├── CMakePresets.json       msvc-x64 / mingw-x64 / clang-cl-x64 / wsl-gcc / wsl-clang
├── cmake/                  options, warnings, config generation, toolchain files
├── config/dev.json         dev configuration (same schema the server will emit)
├── include/sliver/         config.h, log.h, platform.h
├── src/core/               config.c, log.c
├── src/platform/{posix,win32}/
├── src/entry/              main.c (exe), dllmain.c (dll/so)
└── tests/                  ctest: configuration injection assertions
```

## Build

Windows (MSVC, no vcvars needed — Visual Studio generator):

```powershell
cmake --preset msvc-x64
cmake --build --preset msvc-x64
.\build\msvc-x64\bin\Release\implant.exe --self-test
```

Linux (WSL):

```bash
cd /mnt/d/GOPATH/src/C2/sliver/implant-cpp
cmake --preset wsl-gcc
cmake --build --preset wsl-gcc
./build/wsl-gcc/bin/implant --self-test
ctest --test-dir build/wsl-gcc --output-on-failure
```

Windows DLL / Linux .so:

```powershell
cmake --preset msvc-x64-dll
cmake --build --preset msvc-x64-dll
```

MinGW-w64 cross (from WSL, needs `apt install mingw-w64`):

```bash
cmake --preset mingw-x64
cmake --build --preset mingw-x64
```

## Configuration injection

`config/dev.json` is rendered at configure time into:

- `build/<preset>/generated/implant_build_config.h` — switches + numeric constants
- `build/<preset>/generated/implant_secrets.c` — names + C2 URLs (single TU)

The server-side generator will emit the same JSON from `ImplantBuild` (see
`docs/refactor/02-架构设计.md` §8). Every configure also derives a random
`SLIVER_BUILD_SEED`, so two builds from identical inputs differ (equivalent of
`garble -seed=random`).
