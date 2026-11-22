/* POSIX stub: services are a Windows concept. */
#include "sliver/services.h"

int sliver_services_list(sliver_service_t *out, int max) { (void)out; (void)max; return -1; }
int sliver_service_detail(const char *name, sliver_service_t *out) { (void)name; (void)out; return -1; }
int sliver_service_start(const char *name) { (void)name; return -1; }
int sliver_revert_to_self(void) { return -1; }
