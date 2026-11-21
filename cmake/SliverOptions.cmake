# SliverOptions.cmake - all cache options and derived defaults.

set(IMPLANT_FORMAT "exe" CACHE STRING "Artifact format: exe | shared")
set_property(CACHE IMPLANT_FORMAT PROPERTY STRINGS exe shared)

set(SLIVER_CONFIG_JSON "${CMAKE_CURRENT_LIST_DIR}/../config/dev.json"
    CACHE FILEPATH "Path to the implant configuration JSON produced by the server")

option(IMPLANT_DEBUG_LOG   "Compile in debug logging (replaces {{if .Config.Debug}})" OFF)
option(IMPLANT_GUI         "Windows GUI subsystem (equivalent of -H=windowsgui)"    OFF)
option(IMPLANT_WERROR      "Treat warnings as errors"                               OFF)
option(IMPLANT_LTO         "Enable link time optimisation"                          OFF)

# Platform implementation directory (platform/<dir>/thread.c)
if(WIN32)
  set(SLIVER_PLATFORM_DIR "win32")
else()
  set(SLIVER_PLATFORM_DIR "posix")
endif()

# Path scrubbing: keep absolute build paths out of the artifact.
if(MSVC)
  # /pathmap requires the deterministic experiment on MSVC 19.4x
  add_compile_options("/experimental:deterministic" "/pathmap:${CMAKE_SOURCE_DIR}=/src")
else()
  add_compile_options("-ffile-prefix-map=${CMAKE_SOURCE_DIR}=/src")
endif()

if(NOT IMPLANT_DEBUG_LOG)
  add_compile_definitions(SLIVER_RELEASE=1)
endif()
