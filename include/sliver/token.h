/* sliver/token.h - token impersonation (make-token / getsystem / rev2self). */
#ifndef SLIVER_TOKEN_H
#define SLIVER_TOKEN_H

#include <stdint.h>

int sliver_make_token(const char *username, const char *password, const char *domain,
                      uint32_t logon_type);
int sliver_get_system(void);

#endif
