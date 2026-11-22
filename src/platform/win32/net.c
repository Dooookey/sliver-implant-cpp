/* src/platform/win32/net.c - blocking TCP sockets (Win32). */
#include "sliver/platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

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
}
