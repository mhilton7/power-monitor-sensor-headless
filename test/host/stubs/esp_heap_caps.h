#pragma once

#include <stddef.h>
#include <stdlib.h>

#define MALLOC_CAP_SPIRAM 1U
#define MALLOC_CAP_INTERNAL 2U
#define MALLOC_CAP_8BIT 4U

extern int s_test_heap_fail;

static inline void *heap_caps_calloc(size_t count, size_t size, unsigned int capabilities)
{
    (void)capabilities;
    return s_test_heap_fail ? NULL : calloc(count, size);
}

static inline void *heap_caps_malloc(size_t size, unsigned int capabilities)
{
    (void)capabilities;
    return s_test_heap_fail ? NULL : malloc(size);
}

static inline void heap_caps_free(void *value)
{
    free(value);
}
