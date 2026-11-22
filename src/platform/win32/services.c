/* src/platform/win32/services.c - SCM enumeration and control. */
#include "sliver/services.h"

#include "sliver/log.h"

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fill_details(SC_HANDLE scm, const char *name, sliver_service_t *out) {
  SC_HANDLE svc;
  QUERY_SERVICE_CONFIGA *cfg = NULL;
  SERVICE_DESCRIPTIONA *desc = NULL;
  DWORD needed = 0;

  (void)snprintf(out->name, sizeof(out->name), "%s", name);
  svc = OpenServiceA(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
  if (svc == NULL) {
    return;
  }
  (void)QueryServiceConfigA(svc, NULL, 0, &needed);
  if (needed != 0) {
    cfg = (QUERY_SERVICE_CONFIGA *)malloc(needed);
    if (cfg != NULL && QueryServiceConfigA(svc, cfg, needed, &needed)) {
      (void)snprintf(out->display_name, sizeof(out->display_name), "%s", cfg->lpDisplayName != NULL ? cfg->lpDisplayName : "");
      (void)snprintf(out->bin_path, sizeof(out->bin_path), "%s", cfg->lpBinaryPathName != NULL ? cfg->lpBinaryPathName : "");
      (void)snprintf(out->account, sizeof(out->account), "%s", cfg->lpServiceStartName != NULL ? cfg->lpServiceStartName : "");
      out->startup_type = cfg->dwStartType;
    }
    free(cfg);
  }
  needed = 0;
  (void)QueryServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &needed);
  if (needed != 0) {
    desc = (SERVICE_DESCRIPTIONA *)malloc(needed);
    if (desc != NULL && QueryServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, (LPBYTE)desc, needed, &needed)) {
      if (desc->lpDescription != NULL) {
        (void)snprintf(out->description, sizeof(out->description), "%s", desc->lpDescription);
      }
    }
    free(desc);
  }
  {
    SERVICE_STATUS_PROCESS status;
    DWORD got = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &got)) {
      out->status = status.dwCurrentState;
    }
  }
  (void)CloseServiceHandle(svc);
}

int sliver_services_list(sliver_service_t *out, int max) {
  SC_HANDLE scm;
  ENUM_SERVICE_STATUS_PROCESSA *items = NULL;
  DWORD needed = 0;
  DWORD returned = 0;
  DWORD resume = 0;
  int count = 0;

  if (out == NULL || max <= 0) {
    return -1;
  }
  scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
  if (scm == NULL) {
    LOG_DEBUG("services: OpenSCManager failed (%lu)", (unsigned long)GetLastError());
    return -1;
  }
  if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0,
                             &needed, &returned, &resume, NULL)) {
    if (GetLastError() != ERROR_MORE_DATA) {
      (void)CloseServiceHandle(scm);
      return -1;
    }
  }
  if (needed == 0) {
    (void)CloseServiceHandle(scm);
    return 0;
  }
  items = (ENUM_SERVICE_STATUS_PROCESSA *)malloc(needed);
  if (items == NULL) {
    (void)CloseServiceHandle(scm);
    return -1;
  }
  resume = 0;
  if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                             (LPBYTE)items, needed, &needed, &returned, &resume, NULL)) {
    free(items);
    (void)CloseServiceHandle(scm);
    return -1;
  }
  for (DWORD i = 0; i < returned && count < max; ++i) {
    sliver_service_t *it = &out[count];
    memset(it, 0, sizeof(*it));
    fill_details(scm, items[i].lpServiceName, it);
    it->status = items[i].ServiceStatusProcess.dwCurrentState;
    if (it->display_name[0] == 0) {
      (void)snprintf(it->display_name, sizeof(it->display_name), "%s", items[i].lpDisplayName);
    }
    count++;
  }
  free(items);
  (void)CloseServiceHandle(scm);
  return count;
}

int sliver_service_detail(const char *name, sliver_service_t *out) {
  SC_HANDLE scm;
  int rc = -1;

  if (name == NULL || out == NULL || name[0] == 0) {
    return -1;
  }
  scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  fill_details(scm, name, out);
  rc = out->name[0] != 0 && (out->status != 0 || out->display_name[0] != 0) ? 0 : -1;
  (void)CloseServiceHandle(scm);
  return rc;
}

int sliver_service_start(const char *name) {
  SC_HANDLE scm;
  SC_HANDLE svc;
  int rc = -1;

  if (name == NULL || name[0] == 0) {
    return -1;
  }
  scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL) {
    LOG_DEBUG("services: OpenSCManager failed (%lu)", (unsigned long)GetLastError());
    return -1;
  }
  svc = OpenServiceA(scm, name, SERVICE_START | SERVICE_QUERY_STATUS);
  if (svc != NULL) {
    rc = StartServiceA(svc, 0, NULL) ? 0 : -1;
    if (rc != 0) {
      LOG_DEBUG("services: StartService(%s) failed (%lu)", name, (unsigned long)GetLastError());
    }
    (void)CloseServiceHandle(svc);
  }
  (void)CloseServiceHandle(scm);
  return rc;
}

int sliver_revert_to_self(void) { return RevertToSelf() ? 0 : -1; }

