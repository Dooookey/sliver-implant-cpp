/* src/platform/posix/net.c - blocking TCP sockets (POSIX). */
#if !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE < 200809L)
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "sliver/platform.h"

#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct sliver_socket {
  int fd;
};

sliver_socket_t *sliver_tcp_connect(const char *host, uint16_t port) {
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *it;
  char service[8];
  sliver_socket_t *sock = NULL;
  int fd = -1;

  if (host == NULL) {
    return NULL;
  }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
  if (getaddrinfo(host, service, &hints, &res) != 0) {
    return NULL;
  }
  for (it = res; it != NULL; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) {
      continue;
    }
    if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
      sock = (sliver_socket_t *)calloc(1, sizeof(*sock));
      if (sock != NULL) {
        sock->fd = fd;
        fd = -1;
      }
      break;
    }
    (void)close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd >= 0) {
    (void)close(fd);
  }
  return sock;
}

long sliver_socket_send(sliver_socket_t *s, const void *buf, size_t len) {
  ssize_t n;
  if (s == NULL || buf == NULL) {
    return -1;
  }
  n = send(s->fd, buf, len, 0);
  return (long)n;
}

long sliver_socket_recv(sliver_socket_t *s, void *buf, size_t len) {
  ssize_t n;
  if (s == NULL || buf == NULL) {
    return -1;
  }
  n = recv(s->fd, buf, len, 0);
  return (long)n;
}

void sliver_socket_close(sliver_socket_t *s) {
  if (s == NULL) {
    return;
  }
  (void)close(s->fd);
  free(s);
}
