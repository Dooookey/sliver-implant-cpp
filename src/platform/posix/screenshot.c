/* POSIX stub: screen capture is implemented for Windows only. */
#include "sliver/screenshot.h"

int sliver_screenshot_capture(uint8_t **out, size_t *out_len) {
  (void)out;
  (void)out_len;
  return -1;
}
