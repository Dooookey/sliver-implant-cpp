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
void sliver_log_write(sliver_log_level_t level, const char *fmt, ...);

#define LOG_INFO(...)  sliver_log_write(SLIVER_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...)  sliver_log_write(SLIVER_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) sliver_log_write(SLIVER_LOG_ERROR, __VA_ARGS__)

#if defined(SLIVER_DEBUG_LOG) && SLIVER_DEBUG_LOG
#define LOG_DEBUG(...) sliver_log_write(SLIVER_LOG_DEBUG, __VA_ARGS__)
#else
#define LOG_DEBUG(...) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SLIVER_LOG_H */
