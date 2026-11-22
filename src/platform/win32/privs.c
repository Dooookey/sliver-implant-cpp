/* src/platform/win32/privs.c - token privileges and integrity level. */
#include "sliver/privs.h"

#include <windows.h>

#include "sliver/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Built-in descriptions: LookupPrivilegeDisplayName crashes on this host, so the
 * well-known privileges are mapped locally (English text, same meaning). */
static const struct {
  const char *name;
  const char *desc;
} kPrivDesc[] = {
    {"SeShutdownPrivilege", "Shut down the system"},
    {"SeChangeNotifyPrivilege", "Bypass traverse checking"},
    {"SeUndockPrivilege", "Remove computer from docking station"},
    {"SeIncreaseWorkingSetPrivilege", "Increase a process working set"},
    {"SeTimeZonePrivilege", "Change the time zone"},
    {"SeDebugPrivilege", "Debug programs"},
    {"SeImpersonatePrivilege", "Impersonate a client after authentication"},
    {"SeAssignPrimaryTokenPrivilege", "Replace a process level token"},
    {"SeBackupPrivilege", "Back up files and directories"},
    {"SeRestorePrivilege", "Restore files and directories"},
    {"SeTakeOwnershipPrivilege", "Take ownership of files or other objects"},
    {"SeLoadDriverPrivilege", "Load and unload device drivers"},
    {"SeCreateTokenPrivilege", "Create a token object"},
    {"SeTcbPrivilege", "Act as part of the operating system"},
    {"SeSecurityPrivilege", "Manage auditing and security log"},
    {"SeSystemtimePrivilege", "Change the system time"},
    {"SeCreateGlobalPrivilege", "Create global objects"},
    {"SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process"},
    {"SeLockMemoryPrivilege", "Lock pages in memory"},
    {"SeSystemProfilePrivilege", "Profile system performance"},
    {"SeProfileSingleProcessPrivilege", "Profile single process"},
    {"SeCreatePagefilePrivilege", "Create a pagefile"},
    {"SeRemoteShutdownPrivilege", "Force shutdown from a remote system"},
    {"SeManageVolumePrivilege", "Perform volume maintenance tasks"},
    {"SeCreateSymbolicLinkPrivilege", "Create symbolic links"},
    {"SeRelabelPrivilege", "Modify an object label"},
    {"SeDelegateSessionUserImpersonatePrivilege", "Obtain an impersonation token for another user"},
    {"SeAuditPrivilege", "Generate security audits"},
    {"SeSystemEnvironmentPrivilege", "Modify firmware environment values"},
    {"SeEnableDelegationPrivilege", "Enable computer and user accounts to be trusted for delegation"},
};

static const char *priv_description(const char *name) {
  size_t i;
  for (i = 0; i < sizeof(kPrivDesc) / sizeof(kPrivDesc[0]); ++i) {
    if (strcmp(kPrivDesc[i].name, name) == 0) {
      return kPrivDesc[i].desc;
    }
  }
  return name;
}

static const char *integrity_name(DWORD rid) {
  if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return "System";
  if (rid >= SECURITY_MANDATORY_HIGH_RID) return "High";
  if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return "Medium";
  if (rid >= SECURITY_MANDATORY_LOW_RID) return "Low";
  return "Untrusted";
}

int sliver_getprivs(sliver_priv_t *out, int max, char *integrity, size_t integrity_cap,
                    char *process_name, size_t process_name_cap) {
  HANDLE token = NULL;
  DWORD size = 0;
  TOKEN_PRIVILEGES *privs = NULL;
  int count = 0;

  if (out == NULL || max <= 0) {
    return -1;
  }
  if (process_name != NULL && process_name_cap != 0) {
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, sizeof(path));
    const char *base = path;
    for (DWORD i = 0; i < n; ++i) {
      if (path[i] == '\\') {
        base = path + i + 1;
      }
    }
    (void)snprintf(process_name, process_name_cap, "%s", base);
  }
  LOG_DEBUG("privs: open token");
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return -1;
  }
  LOG_DEBUG("privs: token ok");
  LOG_DEBUG("privs: query size");
  (void)GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
  LOG_DEBUG("privs: size=%lu", (unsigned long)size);
  privs = (TOKEN_PRIVILEGES *)calloc(1, (size_t)(size != 0 ? size : sizeof(TOKEN_PRIVILEGES)) + 64);
  if (privs == NULL) {
    (void)CloseHandle(token);
    return -1;
  }
  if (!GetTokenInformation(token, TokenPrivileges, privs, size, &size) ||
      privs->PrivilegeCount > 128) {
    free(privs);
    (void)CloseHandle(token);
    return -1;
  }
  LOG_DEBUG("privs: count=%lu", (unsigned long)privs->PrivilegeCount);
  for (DWORD i = 0; i < privs->PrivilegeCount && count < max; ++i) {
    char name[128] = {0};
    char display[256] = {0};
    DWORD len = sizeof(name);
    DWORD dlen = sizeof(display);
    LUID luid = privs->Privileges[i].Luid;

    if (!LookupPrivilegeNameA(NULL, &luid, name, &len)) {
      continue;
    }
    (void)snprintf(display, sizeof(display), "%s", priv_description(name));
    (void)snprintf(out[count].name, sizeof(out[count].name), "%s", name);
    (void)snprintf(out[count].description, sizeof(out[count].description), "%s", display);
    out[count].enabled = (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
    out[count].enabled_by_default =
        (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
    out[count].removed = (privs->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) != 0;
    count++;
  }
  free(privs);

  if (integrity != NULL && integrity_cap != 0) {
    DWORD isize = 0;
    (void)GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &isize);
    if (isize != 0) {
      TOKEN_MANDATORY_LABEL *label = (TOKEN_MANDATORY_LABEL *)malloc(isize);
      if (label != NULL &&
          GetTokenInformation(token, TokenIntegrityLevel, label, isize, &isize)) {
        if (label->Label.Sid != NULL && IsValidSid(label->Label.Sid)) {
          DWORD count = (DWORD)*GetSidSubAuthorityCount(label->Label.Sid);
          if (count > 0) {
            DWORD rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
            (void)snprintf(integrity, integrity_cap, "%s", integrity_name(rid));
          }
        }
      }
      free(label);
    }
  }
  (void)CloseHandle(token);
  return count;
}









