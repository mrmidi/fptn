/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#ifndef FPTN_LWIP_ARCH_CC_H
#define FPTN_LWIP_ARCH_CC_H

#include <assert.h>
#include <stdint.h>

#define LWIP_NO_STDINT_H 0
#define LWIP_NO_INTTYPES_H 0

#define LWIP_PLATFORM_DIAG(x)
#define LWIP_PLATFORM_ASSERT(x) assert(x)

uint32_t fptn_lwip_rand(void);
#define LWIP_RAND() fptn_lwip_rand()

#endif /* FPTN_LWIP_ARCH_CC_H */
