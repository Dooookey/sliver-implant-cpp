/* sliver/privs.h - token privileges (getprivs). */
#ifndef SLIVER_PRIVS_H
#define SLIVER_PRIVS_H

#include <stddef.h>

#include "sliver/proto.h"

typedef struct {
  char name[128];
  char description[256];
  int enabled;
  int enabled_by_default;
  int removed;
} sliver_priv_t;

/* Fills out[] and the two strings; returns the privilege count or -1. */
int sliver_getprivs(sliver_priv_t *out, int max, char *integrity, size_t integrity_cap,
                    char *process_name, size_t process_name_cap);

/* GetPrivs{PrivInfo=1 repeated, ProcessIntegrity=2, ProcessName=3, Response=9}. */
int sliver_getprivs_encode(sliver_buf_t *out, const sliver_priv_t *privs, int count,
                           const char *integrity, const char *process_name, const char *err);

#endif

