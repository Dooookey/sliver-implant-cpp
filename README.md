# implant-cpp

C/C++ re-implementation of the Sliver implant runtime. The design notes live in the
parent sliver fork under `docs/refactor/` (research, architecture, build system,
milestones, risks, GenerateCpp mirroring, dev environment).

This repository is extracted from the sliver fork with full history
(`git subtree split --prefix=implant-cpp`), so it can be built, versioned and released
on its own. The Go server consumes it either as a submodule or as a subtree.

**Status (P0 skeleton):** toolchain matrix, build-time configuration injection (11 key
slots), platform abstraction, config self-test, static + size gates. The TLS/yamux/
protobuf protocol stack lands in P0 proper.

## Layout

```
.
├── CMakeLists.txt          top level (options → config generation → core lib → artifact)
├── CMakePresets.json       msvc-x64[-debug|-dll] / mingw-x64 / clang-cl-x64 / wsl-gcc[-debug] / wsl-clang / wsl-musl
├── cmake/                  options, warnings, config generation, toolchain files
├── config/dev.json         dev configuration (same schema the server emits)
├── include/sliver/         config.h (incl. secret slots), log.h, platform.h
├── src/core/               config.c, log.c
├── src/platform/{posix,win32}/
├── src/entry/              main.c (exe), dllmain.c (dll/so)
├── tests/                  ctest: configuration injection assertions
└── .github/workflows/ci.yml  linux gcc+clang, mingw cross, msvc, with static/size gates
```

## Build

Windows (MSVC, no vcvars needed — Visual Studio generator):

```powershell
cmake --preset msvc-x64
cmake --build --preset msvc-x64
.\build\msvc-x64\bin\implant.exe --self-test
```

Debug build (breakpoints in VS / CLion):

```powershell
cmake --preset msvc-x64-debug
cmake --build --preset msvc-x64-debug
```

Linux (WSL):

```bash
cmake --preset wsl-gcc
cmake --build --preset wsl-gcc
./build/wsl-gcc/bin/implant --self-test
ctest --test-dir build/wsl-gcc --output-on-failure

# debug (dynamic link + -g3, for gdb/lldb/CLion)
cmake --preset wsl-gcc-debug && cmake --build --preset wsl-gcc-debug
gdb -q ./build/wsl-gcc-debug/bin/implant

# KB-sized static ELF (needs: apt install musl-tools)
cmake --preset wsl-musl && cmake --build --preset wsl-musl
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

## Size and static-link gates

Hard limits enforced in two places (CMake options + server-side `server/cppbuild`):

| Check | Rule |
|---|---|
| static Windows | `/MT` (`IMPLANT_STATIC_CRT=ON`), no `VCRUNTIME140`/`ucrtbase` imports |
| static Linux | `-static` (`IMPLANT_STATIC_LINK=ON` for exe), no `PT_INTERP` |
| size | fail > 5 MiB, warn > 512 KiB (target), stretch goal 150 KiB |

Measured on the skeleton: MSVC `/MT` exe **150,016 B**, WSL gcc `-static` ELF 863,200 B
(glibc; musl preset expected 40–80 KB).

## Configuration injection

`config/dev.json` is rendered at configure time into:

- `build/<preset>/generated/implant_build_config.h` — switches, numeric constants, limits
- `build/<preset>/generated/implant_secrets.c` — names, C2 URLs, 11 key slots (single TU)

The server (`server/cppbuild` in the sliver fork) emits the same JSON from
`clientpb.ImplantConfig` + `clientpb.ImplantBuild`, and validates the resulting artifact
(PE/ELF shape, static linkage, size) before it is returned to the operator.
