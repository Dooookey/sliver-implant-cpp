/* src/platform/win32/dllload.c - load a DLL into the implant process. */
#include "sliver/dllload.h"

#include "sliver/log.h"

#include <windows.h>

#include <stdio.h>

/* Stage C step 1: self-load only. Remote injection is a separate, verified step. */
int sliver_dll_load(const char *path, const char *entrypoint) {
  HMODULE mod;
  DWORD err;

  if (path == NULL || path[0] == 0) {
    return -1;
  }
  mod = LoadLibraryA(path);
  if (mod == NULL) {
    err = GetLastError();
    LOG_DEBUG("dllload: LoadLibrary(%s) failed (%lu)", path, (unsigned long)err);
    return -(int)err;
  }
  LOG_DEBUG("dllload: %s -> 0x%p", path, (void *)mod);
  if (entrypoint != NULL && entrypoint[0] != 0) {
    FARPROC fn = GetProcAddress(mod, entrypoint);
    if (fn == NULL) {
      err = GetLastError();
      LOG_DEBUG("dllload: export %s not found (%lu)", entrypoint, (unsigned long)err);
      return -(int)err;
    }
    /* Zero-argument exports only; the Go implant has the same restriction for
     * its reflective loader stub. */
    {
      typedef int (*sliver_dll_entry_t)(void);
      sliver_dll_entry_t entry = (sliver_dll_entry_t)fn;
      int rc = entry();
      LOG_DEBUG("dllload: %s!%s returned %d", path, entrypoint, rc);
      return rc;
    }
  }
  return 0;
}

int sliver_dll_free(const char *path) {
  HMODULE mod;

  if (path == NULL || path[0] == 0) {
    return -1;
  }
  mod = GetModuleHandleA(path);
  if (mod == NULL) {
    return -1;
  }
  return FreeLibrary(mod) ? 0 : -1;
}
