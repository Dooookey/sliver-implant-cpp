/* src/platform/win32/proc.c - process list/terminate and environment (Win32). */
#include "sliver/proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#define SLIVER_MAX_PROCS 4096
#define SLIVER_MAX_ENV 4096

int sliver_proc_list(sliver_proc_t **out, size_t *count) {
  HANDLE snap;
  PROCESSENTRY32 pe;
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
  snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    free(procs);
    return -1;
  }
  pe.dwSize = sizeof(pe);
  if (Process32First(snap, &pe)) {
    do {
      if (n >= SLIVER_MAX_PROCS) {
        break;
      }
      procs[n].pid = (int32_t)pe.th32ProcessID;
      procs[n].ppid = (int32_t)pe.th32ParentProcessID;
      (void)snprintf(procs[n].exe, sizeof(procs[n].exe), "%s", pe.szExeFile);
      procs[n].session_id = 0;
      (void)snprintf(procs[n].arch, sizeof(procs[n].arch), "%s", "x64");
      n++;
    } while (Process32Next(snap, &pe));
  }
  (void)CloseHandle(snap);

  *out = procs;
  *count = n;
  return 0;
}

void sliver_proc_free(sliver_proc_t *procs) { free(procs); }

int sliver_proc_terminate(int32_t pid, int force) {
  HANDLE h;
  BOOL ok;
  (void)force;
  h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
  if (h == NULL) {
    return -1;
  }
  ok = TerminateProcess(h, 1);
  (void)CloseHandle(h);
  return ok ? 0 : -1;
}

int sliver_env_list(sliver_env_t **out, size_t *count) {
  char *block;
  char *cursor;
  sliver_env_t *vars;
  size_t n = 0;

  if (out == NULL || count == NULL) {
    return -1;
  }
  *out = NULL;
  *count = 0;

  vars = (sliver_env_t *)calloc(SLIVER_MAX_ENV, sizeof(sliver_env_t));
  if (vars == NULL) {
    return -1;
  }
  block = GetEnvironmentStringsA();
  if (block == NULL) {
    free(vars);
    return -1;
  }
  for (cursor = block; *cursor != '\0' && n < SLIVER_MAX_ENV; cursor += strlen(cursor) + 1) {
    const char *eq;
    size_t klen;
    if (cursor[0] == '=') {
      continue; /* hidden drive-current-directory variables */
    }
    eq = strchr(cursor, '=');
    if (eq == NULL) {
      continue;
    }
    klen = (size_t)(eq - cursor);
    if (klen >= sizeof(vars[n].key)) {
      klen = sizeof(vars[n].key) - 1;
    }
    memcpy(vars[n].key, cursor, klen);
    vars[n].key[klen] = '\0';
    (void)snprintf(vars[n].value, sizeof(vars[n].value), "%s", eq + 1);
    n++;
  }
  (void)FreeEnvironmentStringsA(block);
  *out = vars;
  *count = n;
  return 0;
}

void sliver_env_free(sliver_env_t *vars) { free(vars); }

