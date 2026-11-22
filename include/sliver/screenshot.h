/* sliver/screenshot.h - screen capture (Windows JPEG, POSIX unsupported). */
#ifndef SLIVER_SCREENSHOT_H
#define SLIVER_SCREENSHOT_H

#include <stddef.h>
#include <stdint.h>

/* Captures the desktop into a JPEG buffer (caller frees *out). */
int sliver_screenshot_capture(uint8_t **out, size_t *out_len);

#endif
