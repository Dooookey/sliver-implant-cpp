/* src/platform/win32/exec.c - capture a child process (Win32). */
#include "sliver/proc.h"

#include <stdio.h>
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
  if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
    if (capture) {
      (void)CloseHandle(out_r);
      (void)CloseHandle(out_w);
      (void)CloseHandle(err_r);
      (void)CloseHandle(err_w);
    }
    return -1;
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

