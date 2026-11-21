/* src/core/log.c - levelled logger writing to stderr. */
#include "sliver/log.h"

#include <stdarg.h>
#include <stdio.h>

static sliver_log_level_t g_level = SLIVER_LOG_INFO;

static const char *level_name(sliver_log_level_t level) {
  switch (level) {
    case SLIVER_LOG_DEBUG: return "debug";
    case SLIVER_LOG_INFO:  return "info";
    case SLIVER_LOG_WARN:  return "warn";
    case SLIVER_LOG_ERROR: return "error";
    default:               return "?";
  }
}

void sliver_log_set_level(sliver_log_level_t level) { g_level = level; }
sliver_log_level_t sliver_log_get_level(void) { return g_level; }

void sliver_log_write(sliver_log_level_t level, const char *fmt, ...) {
  va_list ap;
  if (fmt == NULL || level < g_level) {
    return;
  }
  (void)fprintf(stderr, "[%-5s] ", level_name(level));
  va_start(ap, fmt);
  (void)vfprintf(stderr, fmt, ap);
  va_end(ap);
  (void)fputc('\n', stderr);
}
