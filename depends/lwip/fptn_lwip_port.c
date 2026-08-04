/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "lwip/arch.h"

u32_t sys_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (u32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

uint32_t fptn_lwip_rand(void) {
#if defined(__APPLE__)
  return arc4random();
#else
  return (uint32_t)rand();
#endif
}
