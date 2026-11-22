/* POSIX stub. */
#include "sliver/dllload.h"

int sliver_dll_load(const char *path, const char *entrypoint) {
  (void)path; (void)entrypoint;
  return -1;
}
int sliver_dll_free(const char *path) { (void)path; return -1; }
