/* src/platform/posix/proc.c - process list/terminate and environment (POSIX). */
#define _POSIX_C_SOURCE 200809L

#include "sliver/proc.h"

#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

#define SLIVER_MAX_PROCS 2048
#define SLIVER_MAX_ENV 1024

static int read_file_line(const char *path, char *buf, size_t cap) {
  FILE *f = fopen(path, "r");
  if (f == NULL) {
    return -1;
  }
  if (fgets(buf, (int)cap, f) == NULL) {
    (void)fclose(f);
    return -1;
  }
  (void)fclose(f);
  buf[strcspn(buf, "\r\n")] = '\0';
  return 0;
}

int sliver_proc_list(sliver_proc_t **out, size_t *count) {
  DIR *dir;
  struct dirent *de;
  sliver_proc_t *procs;
  size_t n = 0;

  if (out == NULL || count == NULL) {
    return -1;
  }
  *out = NULL;
  *count = 0;

  procs = (sliver_proc_t *)calloc(SLIVER_MAX_PROCS, sizeof(sliver_proc_t));
  if (procs == NULL) {
    return -1;
  }
  dir = opendir("/proc");
  if (dir == NULL) {
    free(procs);
    return -1;
  }
  while ((de = readdir(dir)) != NULL && n < SLIVER_MAX_PROCS) {
    char path[256];
    char buf[512];
    char *end = NULL;
    long pid;
    struct stat st;

    pid = strtol(de->d_name, &end, 10);
    if (end == NULL || *end != '\0' || pid <= 0) {
      continue;
    }
    procs[n].pid = (int32_t)pid;
    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
    if (read_file_line(path, buf, sizeof(buf)) == 0) {
      char *rp = strrchr(buf, ')');
      if (rp != NULL) {
        long ppid = 0;
        if (sscanf(rp + 2, "%*c %ld", &ppid) == 1) {
          procs[n].ppid = (int32_t)ppid;
        }
      }
    }
    (void)snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
    if (read_file_line(path, procs[n].exe, sizeof(procs[n].exe)) != 0) {
      (void)snprintf(procs[n].exe, sizeof(procs[n].exe), "?");
    }
    (void)snprintf(path, sizeof(path), "/proc/%ld", pid);
    if (stat(path, &st) == 0) {
      (void)snprintf(procs[n].owner, sizeof(procs[n].owner), "%d", (int)st.st_uid);
    }
    {
      char cmd[512];
      FILE *cf;
      (void)snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
      cf = fopen(path, "rb");
      if (cf != NULL) {
        size_t got = fread(cmd, 1, sizeof(cmd) - 1, cf);
        (void)fclose(cf);
        for (size_t k = 0; k < got; ++k) {
          if (cmd[k] == 0) {
            cmd[k] = (k + 1 < got) ? \' \' : 0;
          }
        }
        cmd[got] = 0;
        (void)snprintf(procs[n].cmdline, sizeof(procs[n].cmdline), "%s", cmd);
      }
    }
    (void)snprintf(procs[n].arch, sizeof(procs[n].arch), "%s", sizeof(void *) == 8 ? "x64" : "x86");
    n++;
  }
  (void)closedir(dir);
  *out = procs;
  *count = n;
  return 0;
}

void sliver_proc_free(sliver_proc_t *procs) { free(procs); }

int sliver_proc_terminate(int32_t pid, int force) {
  return kill((pid_t)pid, force ? SIGKILL : SIGTERM) == 0 ? 0 : -1;
}

int sliver_env_list(sliver_env_t **out, size_t *count) {
  sliver_env_t *vars;
  size_t n = 0;
  char **it;

  if (out == NULL || count == NULL) {
    return -1;
  }
  *out = NULL;
  *count = 0;

  vars = (sliver_env_t *)calloc(SLIVER_MAX_ENV, sizeof(sliver_env_t));
  if (vars == NULL) {
    return -1;
  }
  for (it = environ; it != NULL && *it != NULL && n < SLIVER_MAX_ENV; ++it) {
    const char *eq = strchr(*it, '=');
    size_t klen;
    if (eq == NULL) {
      continue;
    }
    klen = (size_t)(eq - *it);
    if (klen >= sizeof(vars[n].key)) {
      klen = sizeof(vars[n].key) - 1;
    }
    memcpy(vars[n].key, *it, klen);
    vars[n].key[klen] = '\0';
    (void)snprintf(vars[n].value, sizeof(vars[n].value), "%s", eq + 1);
    n++;
  }
  *out = vars;
  *count = n;
  return 0;
}

void sliver_env_free(sliver_env_t *vars) { free(vars); }



