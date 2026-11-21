# SliverOptions.cmake - all cache options and derived defaults.

set(IMPLANT_FORMAT "exe" CACHE STRING "Artifact format: exe | shared")
set_property(CACHE IMPLANT_FORMAT PROPERTY STRINGS exe shared)

set(SLIVER_CONFIG_JSON "${CMAKE_CURRENT_LIST_DIR}/../config/dev.json"
    CACHE FILEPATH "Path to the implant configuration JSON produced by the server")

option(IMPLANT_DEBUG_LOG   "Compile in debug logging (replaces {{if .Config.Debug}})" OFF)
option(IMPLANT_GUI         "Windows GUI subsystem (equivalent of -H=windowsgui)"    OFF)
option(IMPLANT_WERROR      "Treat warnings as errors"                               OFF)
option(IMPLANT_LTO         "Enable link time optimisation (size)"                   ON)
option(IMPLANT_STRIP       "Strip symbols and section garbage (size)"               ON)
option(IMPLANT_STATIC_CRT  "Link the C runtime statically (/MT, -static-libgcc)"    ON)
option(IMPLANT_STATIC_LINK "Fully static ELF link (-static); exe only"              ON)

# Platform implementation directory (platform/<dir>/thread.c)
if(WIN32)
  set(SLIVER_PLATFORM_DIR "win32")
else()
  set(SLIVER_PLATFORM_DIR "posix")
endif()

# --- static runtime -------------------------------------------------------
if(IMPLANT_STATIC_CRT)
  if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded" CACHE STRING "" FORCE)
  endif()
  if(MINGW)
    add_link_options("-static-libgcc" "-static-libstdc++")
  endif()
endif()

# --- size first -----------------------------------------------------------
if(MSVC)
  add_compile_options("/Gy" "/Gw")
  add_link_options("/OPT:REF" "/OPT:ICF")
  if(IMPLANT_LTO)
    add_compile_options("/GL")
    add_link_options("/LTCG")
  endif()
  if(IMPLANT_STRIP)
    add_link_options("/DEBUG:NONE")
  endif()
  # /pathmap requires the deterministic experiment on MSVC 19.4x
  add_compile_options("/experimental:deterministic" "/pathmap:${CMAKE_SOURCE_DIR}=/src")
else()
  add_compile_options("-ffunction-sections" "-fdata-sections")
  add_link_options("-Wl,--gc-sections")
  # A shared library must stay dynamic; a standalone implant must not depend on
  # the target's glibc version, so link it statically.
  if(IMPLANT_STATIC_LINK AND IMPLANT_FORMAT STREQUAL "exe")
    add_link_options("-static")
  endif()
  if(IMPLANT_LTO)
    add_compile_options("-flto")
    add_link_options("-flto")
  endif()
  if(IMPLANT_STRIP)
    add_link_options("-s")
  endif()
  add_compile_options("-ffile-prefix-map=${CMAKE_SOURCE_DIR}=/src")
endif()

if(NOT IMPLANT_DEBUG_LOG)
  add_compile_definitions(SLIVER_RELEASE=1)
endif()
