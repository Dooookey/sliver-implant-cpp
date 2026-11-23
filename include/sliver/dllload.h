/* sliver/dllload.h - load a DLL into the implant process (stage C step 1). */
#ifndef SLIVER_DLLLOAD_H
#define SLIVER_DLLLOAD_H

#ifdef __cplusplus
extern "C" {
#endif

/* Loads path; when entrypoint is non-empty it is called as int(*)(void).
 * Returns 0 on success, a negative Win32 error otherwise. */
int sliver_dll_load(const char *path, const char *entrypoint);
int sliver_dll_free(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_DLLLOAD_H */
