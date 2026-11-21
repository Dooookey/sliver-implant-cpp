/* sliver/proc.h - process and environment inspection used by the RPC layer. */
#ifndef SLIVER_PROC_H
#define SLIVER_PROC_H

#include <stddef.h>
#include <stdint.h>

#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int32_t pid;
  int32_t ppid;
  char exe[256];
  char owner[64];
  int32_t session_id;
  char cmdline[512];
  char arch[16];
} sliver_proc_t;

typedef struct {
  char key[192];
  char value[512];
} sliver_env_t;

/* Returns a malloc'd array (caller frees with sliver_proc_free). */
int sliver_proc_list(sliver_proc_t **out, size_t *count);
void sliver_proc_free(sliver_proc_t *procs);

/* force != 0 uses SIGKILL / TerminateProcess without waiting. */
int sliver_proc_terminate(int32_t pid, int force);

int sliver_env_list(sliver_env_t **out, size_t *count);
void sliver_env_free(sliver_env_t *vars);

/* Runs `path` with `args`, capturing stdout/stderr when capture != 0.
 * Blocks until the child exits (60s cap on Windows). */
int sliver_proc_exec(const char *path, const char *const *args, size_t argc, int capture,
                     sliver_buf_t *out, sliver_buf_t *err, uint32_t *pid_out,
                     uint32_t *status_out);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_PROC_H */
