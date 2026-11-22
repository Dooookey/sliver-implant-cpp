/* sliver/log.h - tiny levelled logger.
 *
 * Release builds compile LOG_DEBUG away entirely (mirrors Sliver's
 * {{if .Config.Debug}} guards which drop error strings in release implants).
 */
#ifndef SLIVER_LOG_H
#define SLIVER_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SLIVER_LOG_DEBUG = 0,
  SLIVER_LOG_INFO,
  SLIVER_LOG_WARN,
  SLIVER_LOG_ERROR
} sliver_log_level_t;

void sliver_log_set_level(sliver_log_level_t level);
sliver_log_level_t sliver_log_get_level(void);
/* Mirrors log output into a file (append). Returns 0 on success.
 * Needed for GUI-subsystem builds where stderr goes nowhere. */
int sliver_log_set_file(const char *path);
/* Applies SLIVER_LOG_LEVEL / SLIVER_LOG_FILE (used by debug builds and by
 * injected payloads that have no console of their own). */
void sliver_log_init_from_env(void);
void sliver_log_close_file(void);
void sliver_log_write(sliver_log_level_t level, const char *fmt, ...);

#define LOG_INFO(...)  sliver_log_write(SLIVER_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...)  sliver_log_write(SLIVER_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) sliver_log_write(SLIVER_LOG_ERROR, __VA_ARGS__)

/* Debug/release policy: --debug builds log to the console (and a file),
 * --release builds are silent (no console, no log output). */
#if defined(SLIVER_DEBUG_LOG) && SLIVER_DEBUG_LOG
#define LOG_DEBUG(...) sliver_log_write(SLIVER_LOG_DEBUG, __VA_ARGS__)
#else
#define LOG_DEBUG(...) ((void)0)
#undef LOG_INFO
#undef LOG_WARN
#undef LOG_ERROR
#define LOG_INFO(...)  ((void)0)
#define LOG_WARN(...)  ((void)0)
#define LOG_ERROR(...) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_LOG_H */

