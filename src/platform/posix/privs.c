/* POSIX stub: token privileges are a Windows concept. */
#include "sliver/privs.h"

int sliver_getprivs(sliver_priv_t *out, int max, char *integrity, size_t integrity_cap,
                    char *process_name, size_t process_name_cap) {
  (void)out; (void)max; (void)integrity; (void)integrity_cap; (void)process_name;
  (void)process_name_cap;
  return -1;
}
