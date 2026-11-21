cmake_minimum_required(VERSION 3.25)

project(sliver_implant
  VERSION 0.1.0
  DESCRIPTION "C/C++ re-implementation of the Sliver implant runtime"
  LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(SliverOptions)
include(SliverWarnings)

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
  src/platform/${SLIVER_PLATFORM_DIR}/thread.c
)

add_library(sliver_core STATIC ${SLIVER_CORE_SOURCES} "${SLIVER_GEN_DIR}/implant_secrets.c")
target_include_directories(sliver_core
  PUBLIC  "${CMAKE_CURRENT_LIST_DIR}/include"
  PRIVATE "${SLIVER_GEN_DIR}")
target_link_libraries(sliver_core PUBLIC Threads::Threads)
# PIC is required when the SHARED artifact links this static library.
set_target_properties(sliver_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(WIN32)
  target_link_libraries(sliver_core PUBLIC ws2_32)
endif()
sliver_apply_warnings(sliver_core)
target_compile_definitions(sliver_core PRIVATE
  SLIVER_BUILD_SEED="${SLIVER_BUILD_SEED}"
  $<$<BOOL:${WIN32}>:_WIN32_WINNT=0x0601;WIN32_LEAN_AND_MEAN;NOMINMAX>)

# ---------------------------------------------------------------------------
# 3) Artifact(s)
# ---------------------------------------------------------------------------
if(IMPLANT_FORMAT STREQUAL "exe")
  add_executable(implant src/entry/main.c)
  target_link_libraries(implant PRIVATE sliver_core)
  sliver_apply_warnings(implant)
  if(WIN32 AND IMPLANT_GUI)
    set_target_properties(implant PROPERTIES WIN32_EXECUTABLE TRUE)
  endif()
elseif(IMPLANT_FORMAT STREQUAL "shared")
  add_library(implant SHARED src/entry/dllmain.c)
  target_link_libraries(implant PRIVATE sliver_core)
  target_compile_definitions(implant PRIVATE IMPLANT_BUILD_DLL=1)
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
