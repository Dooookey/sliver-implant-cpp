/* src/core/log.c - levelled logger writing to stderr (and optionally a file). */
#include "sliver/log.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static sliver_log_level_t g_level = SLIVER_LOG_INFO;
static FILE *g_file = NULL;

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

/* Runtime configuration so an injected DLL can log to a file/console without a
 * rebuild: SLIVER_LOG_LEVEL=debug|info|warn|error, SLIVER_LOG_FILE=<path>. */
void sliver_log_init_from_env(void) {
  const char *level = getenv("SLIVER_LOG_LEVEL");
  const char *path = getenv("SLIVER_LOG_FILE");

  if (level != NULL) {
    if (strcmp(level, "debug") == 0) {
      g_level = SLIVER_LOG_DEBUG;
    } else if (strcmp(level, "warn") == 0) {
      g_level = SLIVER_LOG_WARN;
    } else if (strcmp(level, "error") == 0) {
      g_level = SLIVER_LOG_ERROR;
    } else if (strcmp(level, "info") == 0) {
      g_level = SLIVER_LOG_INFO;
    }
  }
  if (path != NULL && path[0] != '\0') {
    (void)sliver_log_set_file(path);
  }
}
sliver_log_level_t sliver_log_get_level(void) { return g_level; }

int sliver_log_set_file(const char *path) {
  FILE *f;
  if (path == NULL) {
    return -1;
  }
  f = fopen(path, "a");
  if (f == NULL) {
    return -1;
  }
  if (g_file != NULL) {
    (void)fclose(g_file);
  }
  g_file = f;
  return 0;
}

void sliver_log_close_file(void) {
  if (g_file != NULL) {
    (void)fclose(g_file);
    g_file = NULL;
  }
}

void sliver_log_write(sliver_log_level_t level, const char *fmt, ...) {
  char message[1024];
  va_list ap;

  if (fmt == NULL || level < g_level) {
    return;
  }
  va_start(ap, fmt);
  (void)vsnprintf(message, sizeof(message), fmt, ap);
  va_end(ap);

  (void)fprintf(stderr, "[%-5s] %s\n", level_name(level), message);
  if (g_file != NULL) {
    (void)fprintf(g_file, "[%-5s] %s\n", level_name(level), message);
    (void)fflush(g_file);
  }
}


